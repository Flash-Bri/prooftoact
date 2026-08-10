import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign, verify } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import { canonicalJson } from "../src/cloud/canonical-json.js";
import {
  integratedLiveDrillCanonicalSha256,
  signIntegratedLiveDrillEvidence
} from "../src/cloud/integrated-live-drill-authorization.js";
import { verifyIntegratedLiveDrillConsumedChildLaunch } from
  "../src/cloud/integrated-live-drill-child-authorization.js";
import {
  recoveryBrokerConfigDigest,
  verifyRecoveryBundleSourceSignature as
    verifyRecoveryBundleSourceSignatureForContinuity
} from "../src/cloud/recovery-continuity-identity.js";
import {
  RECOVERY_PUBLISHER_VERSION,
  RECOVERY_SIGNATURE_ALGORITHM,
  verifyRecoveryBundleSourceSignature as
    verifyRecoveryBundleSourceSignatureForProduction
} from "../src/cloud/recovery-store.js";
import { createSyntheticRecoverySigner } from
  "../scripts/lib/synthetic-recovery-signer.js";
import {
  INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE,
  INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN,
  INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_UNKNOWN,
  integratedLiveDrillRecoveryContinuityPreCallIntent,
  inspectIntegratedLiveDrillRecoveryContinuity,
  runIntegratedLiveDrillRecoveryContinuityW1,
  runIntegratedLiveDrillRecoveryContinuityW2,
  runIntegratedLiveDrillRecoveryContinuityW3,
  runIntegratedLiveDrillRecoveryContinuityW4,
  runIntegratedLiveDrillRecoveryContinuityW5,
  validateIntegratedLiveDrillRecoveryContinuityPreCallIntent,
  validateIntegratedLiveDrillRecoveryContinuityJournal
} from "../src/cloud/integrated-live-drill-recovery-continuity.js";
import { createRecoveryContinuityFixture } from
  "./helpers/integrated-live-drill-recovery-continuity-fixture.js";

const WORKER = new URL(
  "./helpers/integrated-live-drill-recovery-continuity-worker.js",
  import.meta.url
);
function fixture(t, prefix = "prooftoact-packet-b-", fakeDelayMs = 0) {
  return createRecoveryContinuityFixture(t, { prefix, fakeDelayMs });
}

function createRawAdversarialRecoverySigner() {
  const publisherKeyId = "adversarial-strict-parity-p256-v1";
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256"
  });
  const publicKeySpkiBase64 = publicKey
    .export({ type: "spki", format: "der" })
    .toString("base64");
  return Object.freeze({
    publisherKeyId,
    publicKeySpkiBase64,
    signRaw(unsignedInput) {
      const unsigned = {
        ...unsignedInput,
        publisherKeyId,
        publisherVersion: RECOVERY_PUBLISHER_VERSION,
        signatureAlgorithm: RECOVERY_SIGNATURE_ALGORITHM
      };
      const bundleDigest = createHash("sha256")
        .update(canonicalJson(unsigned))
        .digest("hex");
      const signature = sign(
        "sha256",
        Buffer.from(`tideproof-recovery-bundle-v2\n${bundleDigest}`, "utf8"),
        privateKey
      );
      return Object.freeze({
        ...unsigned,
        bundleDigest,
        sourceSignatureBase64: signature.toString("base64"),
        signatureDigest: createHash("sha256").update(signature).digest("hex")
      });
    },
    verifyRaw(bundle, expectedBundleDigest = bundle.bundleDigest) {
      return verify(
        "sha256",
        Buffer.from(
          `tideproof-recovery-bundle-v2\n${expectedBundleDigest}`,
          "utf8"
        ),
        publicKey,
        Buffer.from(bundle.sourceSignatureBase64, "base64")
      );
    }
  });
}

function intentFor(
  value,
  preCallInputs = value.context.preCallInputs,
  trustedRunContext = value.context.trustedRunContext
) {
  return integratedLiveDrillRecoveryContinuityPreCallIntent({
    ...preCallInputs,
    authorization: value.context.authorization,
    ledgerRootPath: value.context.ledgerRootPath,
    forbiddenRootPath: value.context.forbiddenRootPath,
    recoveryEvidenceRootPath: value.context.recoveryEvidenceRootPath,
    trustedRunContext,
    now: value.testOnly.now + 200
  });
}

function brokerConfigurationFor(
  value,
  {
    expectedSourceClusterId =
      value.context.trustedRunContext.recoveryBrokerConfiguration
        .expectedSourceClusterId,
    recoveryClusterId =
      value.context.trustedRunContext.recoveryBrokerConfiguration
        .recoveryClusterId
  } = {}
) {
  return Object.freeze({
    expectedSourceClusterId,
    recoveryBrokerConfigDigest: recoveryBrokerConfigDigest({
      recoveryClusterId,
      expectedSourceClusterId,
      buildIdentity: value.context.trustedRunContext.spec.sourceBuildIdentity,
      trustedPublisherKeys:
        value.context.trustedRunContext.committedTrustRoot.trustedPublisherKeys
    }),
    recoveryClusterId
  });
}

function minimalW5Context(value) {
  return Object.freeze({
    authorization: value.context.authorization,
    controlLedgerReceipt: value.context.controlLedgerReceipt,
    forbiddenRootPath: value.context.forbiddenRootPath,
    ledgerRootPath: value.context.ledgerRootPath
  });
}

function sanitizedEnvironment(extra = {}) {
  return Object.freeze({
    PATH: process.env.PATH,
    ...extra
  });
}

function runWorker(value, worker, ...args) {
  return spawnSync(
    process.execPath,
    [WORKER.pathname, "--fixture", value.fixturePath, "--worker", worker, ...args],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      env: sanitizedEnvironment()
    }
  );
}

function runWorkerAsync(value, worker, ...args) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [WORKER.pathname, "--fixture", value.fixturePath, "--worker", worker, ...args],
      {
        cwd: process.cwd(),
        env: sanitizedEnvironment(),
        stdio: ["ignore", "pipe", "pipe"]
      }
    );
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    child.once("close", (status) => resolve({ status, stdout, stderr }));
  });
}

async function releaseBarrier(directory, expectedWorkers) {
  const deadline = Date.now() + 10_000;
  while (
    fs.readdirSync(directory).filter((name) => name.endsWith(".ready")).length <
      expectedWorkers
  ) {
    if (Date.now() >= deadline) {
      throw new Error("TEST_RECOVERY_CONTINUITY_BARRIER_TIMEOUT");
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  fs.writeFileSync(path.join(directory, "release"), "release\n", {
    flag: "wx",
    mode: 0o600
  });
}

function callCount(value) {
  if (!fs.existsSync(value.counterPath)) return 0;
  return fs.readFileSync(value.counterPath, "utf8")
    .split("\n")
    .filter(Boolean)
    .length;
}

function journalCount(value) {
  return fs.readdirSync(value.context.ledgerRootPath)
    .filter((name) => name.includes(".recovery-continuity."))
    .length;
}

test("five subprocess workers resume four failpoints with exactly one fake MCP call", (t) => {
  const value = fixture(t);
  let child = runWorker(
    value,
    "W1",
    "--crash-after",
    "PRE_READ_CHECKPOINT"
  );
  assert.notEqual(child.status, 0);
  assert.match(child.stderr, /SYNTHETIC_CRASH_PRE_READ_CHECKPOINT/u);
  assert.equal(journalCount(value), 3);
  assert.equal(runWorker(value, "W1").status, 0);
  assert.equal(journalCount(value), 4);

  child = runWorker(
    value,
    "W2",
    "--crash-after",
    "MCP_RESULT_AND_CLOSE_DURABLE"
  );
  assert.notEqual(child.status, 0);
  assert.match(child.stderr, /SYNTHETIC_CRASH_MCP_RESULT_AND_CLOSE_DURABLE/u);
  assert.equal(callCount(value), 1);
  assert.equal(journalCount(value), 8);
  child = runWorker(value, "W2", "--no-client");
  assert.equal(child.status, 0, child.stderr);
  assert.equal(callCount(value), 1);
  assert.equal(journalCount(value), 9);

  child = runWorker(
    value,
    "W3",
    "--crash-after",
    "TERMINAL_AUDIT_ROW_VISIBLE_ACK_LOSS"
  );
  assert.notEqual(child.status, 0);
  assert.equal(journalCount(value), 11);
  assert.equal(runWorker(value, "W3").status, 0);
  assert.equal(journalCount(value), 12);

  child = runWorker(
    value,
    "W4",
    "--crash-after",
    "RECEIPT_DURABLE_PUBLICATION_LOSS"
  );
  assert.notEqual(child.status, 0);
  assert.equal(journalCount(value), 14);
  assert.equal(runWorker(value, "W4").status, 0);
  assert.equal(journalCount(value), 15);

  child = runWorker(value, "W5", "--no-client");
  assert.equal(child.status, 0, child.stderr);
  assert.equal(journalCount(value), 17);
  assert.equal(callCount(value), 1);
  const receipt = validateIntegratedLiveDrillRecoveryContinuityJournal(
    value.context
  );
  assert.equal(receipt.status, INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE);
  assert.equal(receipt.entryCount, 17);
  assert.equal(receipt.entryDigests.length, 17);
  assert.equal(receipt.exactMcpCallClaimCount, 1);
  assert.equal(receipt.exactMcpDispatchMarkerCount, 1);
  assert.equal(receipt.reconciledWithoutRetry, true);
  assert.equal(receipt.providerBacked, false);
  assert.equal(receipt.providerCallCountProven, false);
  assert.equal(receipt.liveProviderDispatchAuthorizationProven, false);
  assert.equal(receipt.liveProviderBoundW1W5ContinuityProven, false);
  assert.equal(receipt.localSameHostScaffoldValidated, true);
  assert.match(receipt.claimBoundary, /Local same-host scaffold only/u);
  assert.match(
    receipt.claimBoundary,
    /actual provider-bound W1-W5 continuity remains unproven/u
  );
  assert.match(
    receipt.claimBoundary,
    /records truthful post-dispatch evidence after authority expiry/u
  );
  assert.match(
    receipt.claimBoundary,
    /provider-bound persistence and crash reconciliation.*remain unproven/u
  );
  assert.doesNotMatch(
    receipt.claimBoundary,
    /cannot yet persist post-dispatch evidence after authority expiry/u
  );
  assert.match(
    receipt.claimBoundary,
    /not independently anchored against same-owner full-chain rewriting/u
  );
  assert.equal(receipt.mcpResultSha256, "9".repeat(64));
  assert.equal(receipt.sessionClosed, true);
  assert.deepEqual(
    INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_PLAN.map(({ sequence }) => sequence),
    Array.from({ length: 17 }, (_, index) => index + 1)
  );
});

test("only the O_EXCL claim creator dispatches across synchronized subprocess races", async (t) => {
  const rounds = 5;
  const workerCount = 8;
  for (let round = 0; round < rounds; round += 1) {
    const value = fixture(
      t,
      `prooftoact-packet-b-race-${round}-`,
      100
    );
    assert.equal(runWorker(value, "W1").status, 0);
    const barrierDirectory = path.join(
      value.context.ledgerRootPath,
      "w2-start-barrier"
    );
    fs.mkdirSync(barrierDirectory, { mode: 0o700 });
    const attemptsPromise = Promise.all(Array.from(
      { length: workerCount },
      () => runWorkerAsync(
        value,
        "W2",
        "--barrier-directory",
        barrierDirectory
      )
    ));
    await releaseBarrier(barrierDirectory, workerCount);
    const attempts = await attemptsPromise;
    assert.equal(
      attempts.every(({ status }) => status === 0),
      true,
      attempts.map(({ stderr }) => stderr).join("\n")
    );
    const dispositions = attempts.map(({ stdout }) => JSON.parse(stdout).status);
    assert.equal(
      dispositions.every((status) => [
        INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE,
        INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_UNKNOWN
      ].includes(status)),
      true
    );
    assert.equal(
      dispositions.filter(
        (status) => status === INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_UNKNOWN
      ).length >= workerCount - 1,
      true
    );
    assert.equal(callCount(value), 1);
    const claim = JSON.parse(fs.readFileSync(
      path.join(
        value.context.ledgerRootPath,
        fs.readdirSync(value.context.ledgerRootPath).find((name) =>
          name.includes("06.mcp-call-claimed")
        )
      ),
      "utf8"
    ));
    const dispatch = JSON.parse(fs.readFileSync(
      path.join(
        value.context.ledgerRootPath,
        fs.readdirSync(value.context.ledgerRootPath).find((name) =>
          name.includes("07.mcp-dispatch-marker-durable")
        )
      ),
      "utf8"
    ));
    assert.match(claim.artifact.attemptOwnershipTokenSha256, /^[0-9a-f]{64}$/u);
    assert.equal(
      dispatch.artifact.attemptOwnershipTokenSha256,
      claim.artifact.attemptOwnershipTokenSha256
    );
    assert.equal(
      [
        INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_COMPLETE,
        INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_UNKNOWN
      ].includes(
        inspectIntegratedLiveDrillRecoveryContinuity(value.context).status
      ),
      true
    );
  }
});

test("claimed call without durable completion is permanently unknown and never retried", (t) => {
  const value = fixture(t, "prooftoact-packet-b-unknown-");
  assert.equal(runWorker(value, "W1").status, 0);
  const crashed = runWorker(
    value,
    "W2",
    "--crash-after",
    "MCP_CALL_CLAIMED"
  );
  assert.notEqual(crashed.status, 0);
  assert.equal(journalCount(value), 6);
  assert.equal(callCount(value), 0);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const reconciled = runWorker(value, "W2");
    assert.equal(reconciled.status, 0, reconciled.stderr);
    assert.equal(
      JSON.parse(reconciled.stdout).status,
      INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_UNKNOWN
    );
    assert.equal(callCount(value), 0);
    assert.equal(journalCount(value), 6);
  }
  assert.deepEqual(
    inspectIntegratedLiveDrillRecoveryContinuity(value.context),
    { status: INTEGRATED_LIVE_DRILL_RECOVERY_CONTINUITY_UNKNOWN,
      retryPermitted: false }
  );
  assert.equal(
    fs.readdirSync(value.context.ledgerRootPath).some((name) =>
      name.endsWith("recovery-continuity-unknown-do-not-act.json")
    ),
    true
  );
  assert.throws(
    () => validateIntegratedLiveDrillRecoveryContinuityJournal(value.context),
    /RECOVERY_CONTINUITY_AMBIGUOUS/u
  );
  const w5 = runWorker(value, "W5", "--no-client");
  assert.notEqual(w5.status, 0);
  assert.match(w5.stderr, /W5_RECONCILIATION_REJECTED/u);
});

test("W5 makes no ambient-credential claim, rejects a provider client, and journals reject tampering", (t) => {
  const value = fixture(t, "prooftoact-packet-b-w5-");
  assert.equal(runWorker(value, "W1").status, 0);
  assert.equal(runWorker(value, "W2").status, 0);
  assert.equal(runWorker(value, "W3").status, 0);
  assert.equal(runWorker(value, "W4").status, 0);
  const credentialFile = path.join(
    value.context.ledgerRootPath,
    "synthetic-credentials"
  );
  fs.writeFileSync(credentialFile, "[test]\nkey=value\n", { mode: 0o600 });
  const ambientCredentialConfiguration = spawnSync(
    process.execPath,
    [
      WORKER.pathname,
      "--fixture",
      value.fixturePath,
      "--worker",
      "W5",
      "--no-client"
    ],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      env: sanitizedEnvironment({
        AWS_PROFILE: "test",
        AWS_SHARED_CREDENTIALS_FILE: credentialFile,
        MCP_API_KEY: "synthetic-test-only"
      })
    }
  );
  assert.equal(
    ambientCredentialConfiguration.status,
    0,
    ambientCredentialConfiguration.stderr
  );
  assert.throws(
    () => runIntegratedLiveDrillRecoveryContinuityW5(
      minimalW5Context(value),
      { providerClient: Object.freeze({}) }
    ),
    /W5_PROVIDER_CLIENT_REJECTED/u
  );
  assert.throws(
    () => runIntegratedLiveDrillRecoveryContinuityW5(
      { ...minimalW5Context(value), mcpClient: Object.freeze({}) },
      {}
    ),
    /W5_PROVIDER_CLIENT_REJECTED/u
  );
  assert.throws(
    () => runIntegratedLiveDrillRecoveryContinuityW5(
      minimalW5Context(value),
      { apiKey: "synthetic-test-only" }
    ),
    /W5_PROVIDER_CLIENT_REJECTED/u
  );
  const receipt = validateIntegratedLiveDrillRecoveryContinuityJournal(
    value.context
  );
  assert.equal(receipt.providerBacked, false);
  assert.equal(receipt.providerCallCountProven, false);
  assert.equal(receipt.liveProviderDispatchAuthorizationProven, false);
  const entry = fs.readdirSync(value.context.ledgerRootPath)
    .find((name) => name.includes("08.mcp-result-and-close-durable"));
  const entryPath = path.join(value.context.ledgerRootPath, entry);
  const parsed = JSON.parse(fs.readFileSync(entryPath, "utf8"));
  parsed.artifact.mcpResultSha256 = "0".repeat(64);
  fs.writeFileSync(entryPath, `${canonicalJson(parsed)}\n`, { mode: 0o600 });
  assert.throws(
    () => validateIntegratedLiveDrillRecoveryContinuityJournal(value.context),
    /RECOVERY_CONTINUITY_AMBIGUOUS/u
  );
});

test("pre-call intent is non-circular and W1 rejects fabricated or overriding inputs", (t) => {
  const value = fixture(t, "prooftoact-provider-continuity-intent-");
  const intent = value.context.preCallIntent;
  assert.equal("candidateReceiptSha256" in intent, false);
  assert.equal("mcpRequestSha256" in intent, false);
  assert.match(intent.logicalMcpRequestSha256, /^[0-9a-f]{64}$/u);
  assert.equal(
    intent.expectedSourceClusterId,
    value.context.trustedRunContext.recoveryBrokerConfiguration
      .expectedSourceClusterId
  );
  assert.equal(intent.sourceClusterId, intent.expectedSourceClusterId);
  assert.notEqual(intent.sourceClusterId, intent.recoveryClusterId);
  assert.equal(
    intent.recoveryBrokerConfigDigest,
    value.context.trustedRunContext.recoveryBrokerConfiguration
      .recoveryBrokerConfigDigest
  );
  assert.equal(intentFor(value).intentSha256, intent.intentSha256);
  const beforeReadOnlyChildVerification = fs.readdirSync(
    value.context.ledgerRootPath
  ).sort();
  const verifiedChild = verifyIntegratedLiveDrillConsumedChildLaunch(
    value.testOnly.childEnvironment,
    "MANAGED_MCP_RECOVERY",
    {
      launchReceipt:
        value.context.preCallInputs.consumedManagedMcpLaunch,
      forbiddenRootPath: value.context.forbiddenRootPath,
      now: value.testOnly.now + 200
    }
  );
  assert.equal(verifiedChild.launchReceipt.sequence, 3);
  assert.deepEqual(
    fs.readdirSync(value.context.ledgerRootPath).sort(),
    beforeReadOnlyChildVerification
  );
  assert.equal(
    validateIntegratedLiveDrillRecoveryContinuityPreCallIntent(intent, {
      authorization: value.context.authorization,
      controlLedgerReceipt: value.context.controlLedgerReceipt
    }),
    intent
  );

  const { intentSha256: _intentSha256, ...body } = intent;
  const fabricatedBody = Object.freeze({
    ...body,
    tenantId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
  });
  const fabricated = Object.freeze({
    ...fabricatedBody,
    intentSha256: integratedLiveDrillCanonicalSha256(fabricatedBody)
  });
  assert.throws(
    () => runIntegratedLiveDrillRecoveryContinuityW1({
      ...value.context,
      preCallIntent: fabricated
    }),
    /RECOVERY_CONTINUITY_BINDING_REJECTED/u
  );
  for (const injected of [
    { authorization: value.context.authorization },
    { ledgerRootPath: value.context.ledgerRootPath },
    { forbiddenRootPath: value.context.forbiddenRootPath },
    { preCallIntent: intent }
  ]) {
    assert.throws(
      () => runIntegratedLiveDrillRecoveryContinuityW1({
        ...value.context,
        preCallInputs: {
          ...value.context.preCallInputs,
          ...injected
        }
      }),
      /RECOVERY_CONTINUITY_BINDING_REJECTED/u
    );
  }
});

test("production and continuity share strict trusted-bundle validation", (t) => {
  const value = fixture(t, "prooftoact-provider-continuity-bundle-parity-");
  const rawSigner = createRawAdversarialRecoverySigner();
  const trustedPublisherKeys = Object.freeze({
    [rawSigner.publisherKeyId]: rawSigner.publicKeySpkiBase64
  });
  const {
    bundleDigest: _bundleDigest,
    signatureDigest: _signatureDigest,
    sourceSignatureBase64: _sourceSignatureBase64,
    ...unsigned
  } = value.persistedBundle.bundle;
  const valid = rawSigner.signRaw(unsigned);
  assert.equal(rawSigner.verifyRaw(valid), true);
  assert.equal(
    verifyRecoveryBundleSourceSignatureForContinuity,
    verifyRecoveryBundleSourceSignatureForProduction
  );
  assert.deepEqual(
    verifyRecoveryBundleSourceSignatureForProduction(
      valid,
      trustedPublisherKeys
    ),
    valid
  );
  assert.deepEqual(
    verifyRecoveryBundleSourceSignatureForContinuity(
      valid,
      trustedPublisherKeys
    ),
    valid
  );

  const {
    schemaVersion: _missingSchemaVersion,
    ...withoutSchemaVersion
  } = valid;
  const {
    bundleDigest: _missingBundleDigest,
    ...withoutBundleDigest
  } = valid;
  const {
    signatureDigest: _missingSignatureDigest,
    ...withoutSignatureDigest
  } = valid;
  const {
    authorityTransferred: _missingAuthorityTransferred,
    ...withoutAuthorityTransferred
  } = valid;
  const {
    requiresFreshAuthorization: _missingFreshAuthorization,
    ...withoutFreshAuthorization
  } = valid;
  const unchangedSignatureAdversaries = [
    {
      name: "non-plain top-level object",
      value: Object.assign(
        Object.create({ inheritedByVerifier: "must-reject" }),
        valid
      )
    },
    {
      name: "extra top-level field",
      value: { ...valid, ignoredByNormalizer: "must-reject" }
    },
    { name: "missing schemaVersion", value: withoutSchemaVersion },
    { name: "missing bundleDigest", value: withoutBundleDigest },
    { name: "missing signatureDigest", value: withoutSignatureDigest },
    {
      name: "missing authorityTransferred",
      value: withoutAuthorityTransferred
    },
    {
      name: "missing requiresFreshAuthorization",
      value: withoutFreshAuthorization
    },
    {
      name: "authorityTransferred true",
      value: { ...valid, authorityTransferred: true }
    },
    {
      name: "requiresFreshAuthorization false",
      value: { ...valid, requiresFreshAuthorization: false }
    }
  ];
  for (const adversary of unchangedSignatureAdversaries) {
    assert.equal(
      rawSigner.verifyRaw(adversary.value, valid.bundleDigest),
      true,
      `${adversary.name} must retain a valid trusted signature`
    );
    const failures = [
      verifyRecoveryBundleSourceSignatureForProduction,
      verifyRecoveryBundleSourceSignatureForContinuity
    ].map((verifier) => {
      try {
        verifier(adversary.value, trustedPublisherKeys);
      } catch (error) {
        return error;
      }
      return null;
    });
    assert.equal(
      failures.every((error) => error instanceof Error),
      true,
      `${adversary.name} must fail both verifier imports`
    );
    assert.equal(failures[0].constructor, failures[1].constructor);
    assert.equal(failures[0].message, failures[1].message);
  }

  const sourceCommitMs = Date.parse(unsigned.sourceCommitTs);
  const malformedInputs = [
    {
      name: "object policyVersion",
      value: { ...unsigned, policyVersion: { version: "test-only" } }
    },
    {
      name: "object failedAgent",
      value: {
        ...unsigned,
        checkpointSummary: {
          ...unsigned.checkpointSummary,
          failedAgent: { name: "test-only" }
        }
      }
    },
    {
      name: "excess evidence count",
      value: {
        ...unsigned,
        evidenceSummary: {
          ...unsigned.evidenceSummary,
          admittedCount: 101
        }
      }
    },
    {
      name: "unsupported evidence classification",
      value: {
        ...unsigned,
        evidenceSummary: {
          ...unsigned.evidenceSummary,
          classification: "provider-backed"
        }
      }
    },
    {
      name: "excess conflict count",
      value: {
        ...unsigned,
        conflictSummary: {
          ...unsigned.conflictSummary,
          unresolvedCount: 101
        }
      }
    },
    {
      name: "string durable intent",
      value: {
        ...unsigned,
        receiptSummary: {
          ...unsigned.receiptSummary,
          durableIntentPresent: "true"
        }
      }
    },
    {
      name: "overlong TTL",
      value: {
        ...unsigned,
        expiresAt: new Date(
          sourceCommitMs + (24 * 60 * 60 * 1_000) + 1
        ).toISOString()
      }
    }
  ];
  for (const adversary of malformedInputs) {
    const correctlySignedMalformed = rawSigner.signRaw(adversary.value);
    assert.equal(
      rawSigner.verifyRaw(correctlySignedMalformed),
      true,
      `${adversary.name} must carry a valid trusted raw signature`
    );
    const failures = [
      verifyRecoveryBundleSourceSignatureForProduction,
      verifyRecoveryBundleSourceSignatureForContinuity
    ].map((verifier) => {
      try {
        verifier(correctlySignedMalformed, trustedPublisherKeys);
      } catch (error) {
        return error;
      }
      return null;
    });
    assert.equal(
      failures.every((error) => error instanceof Error),
      true,
      `${adversary.name} must fail both verifier imports`
    );
    assert.equal(failures[0].constructor, failures[1].constructor);
    assert.equal(failures[0].message, failures[1].message);
  }
});

test("trusted roots, source, subject, and persisted bundle cannot be swapped", (t) => {
  const value = fixture(t, "prooftoact-provider-continuity-swaps-");
  const replacementPublisher = createSyntheticRecoverySigner({
    publisherKeyId: value.persistedBundle.bundle.publisherKeyId
  });
  assert.throws(
    () => verifyRecoveryBundleSourceSignatureForContinuity(
      value.persistedBundle.bundle,
      {
        [replacementPublisher.publisherKeyId]:
          replacementPublisher.publicKeySpkiBase64
      }
    ),
    /RECOVERY_SIGNATURE_INVALID/u
  );
  assert.throws(
    () => integratedLiveDrillRecoveryContinuityPreCallIntent({
      ...value.context.preCallInputs,
      authorization: value.context.authorization,
      ledgerRootPath: value.context.ledgerRootPath,
      forbiddenRootPath: value.context.forbiddenRootPath,
      recoveryEvidenceRootPath: value.context.recoveryEvidenceRootPath,
      trustedRunContext: {
        ...value.context.trustedRunContext,
        humanAuthorizationTrustRoot: {
          ...value.context.trustedRunContext.humanAuthorizationTrustRoot,
          keyIdSha256: "0".repeat(64)
        }
      },
      now: value.testOnly.now + 200
    }),
    /INTEGRATED_LIVE_DRILL/u
  );
  assert.throws(
    () => intentFor(value, {
      ...value.context.preCallInputs,
      recoverySourceReceipt: {
        ...value.context.preCallInputs.recoverySourceReceipt,
        tenant_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
      }
    }),
    /RECOVERY_CONTINUITY_BINDING_REJECTED/u
  );
  const sourceClusterId =
    value.context.trustedRunContext.recoveryBrokerConfiguration
      .expectedSourceClusterId;
  const recoveryClusterId =
    value.context.trustedRunContext.recoveryBrokerConfiguration
      .recoveryClusterId;
  const trustedContextWith = (recoveryBrokerConfiguration) => Object.freeze({
    ...value.context.trustedRunContext,
    recoveryBrokerConfiguration
  });
  assert.throws(
    () => intentFor(
      value,
      value.context.preCallInputs,
      trustedContextWith(brokerConfigurationFor(value, {
        expectedSourceClusterId:
          "66666666-6666-4666-8666-666666666666"
      }))
    ),
    /RECOVERY_CONTINUITY_BINDING_REJECTED/u
  );
  assert.throws(
    () => intentFor(
      value,
      value.context.preCallInputs,
      trustedContextWith(brokerConfigurationFor(value, {
        expectedSourceClusterId: recoveryClusterId
      }))
    ),
    /RECOVERY_CONTINUITY_BINDING_REJECTED/u
  );
  assert.throws(
    () => intentFor(
      value,
      {
        ...value.context.preCallInputs,
        recoveryBinding: {
          ...value.context.preCallInputs.recoveryBinding,
          recoveryClusterId: sourceClusterId
        }
      },
      trustedContextWith(brokerConfigurationFor(value, {
        expectedSourceClusterId: recoveryClusterId,
        recoveryClusterId: sourceClusterId
      }))
    ),
    /RECOVERY_CONTINUITY_BINDING_REJECTED/u
  );
  assert.throws(
    () => intentFor(value, {
      ...value.context.preCallInputs,
      recoveryBinding: {
        ...value.context.preCallInputs.recoveryBinding,
        recoveryClusterId:
          "66666666-6666-4666-8666-666666666666"
      }
    }),
    /RECOVERY_CONTINUITY_BINDING_REJECTED/u
  );
  assert.throws(
    () => intentFor(value, {
      ...value.context.preCallInputs,
      recoveryBinding: {
        ...value.context.preCallInputs.recoveryBinding,
        subjectBindingSha256: "0".repeat(64)
      }
    }),
    /RECOVERY_CONTINUITY_BINDING_REJECTED/u
  );
  const { receiptSha256: _receiptSha256, ...receiptBody } =
    value.context.preCallInputs.signedBundlePersistenceReceipt;
  const fabricatedReceiptBody = {
    ...receiptBody,
    pathSha256: "0".repeat(64)
  };
  assert.throws(
    () => intentFor(value, {
      ...value.context.preCallInputs,
      signedBundlePersistenceReceipt: {
        ...fabricatedReceiptBody,
        receiptSha256: integratedLiveDrillCanonicalSha256(
          fabricatedReceiptBody
        )
      }
    }),
    /RECOVERY_BUNDLE_PERSISTENCE_REJECTED/u
  );
  const childAttestation =
    value.context.preCallInputs.consumedChildAuthorization.attestation;
  for (const payload of [
    { ...childAttestation.payload, unexpected: "field" },
    { ...childAttestation.payload, nonceSha256: "not-a-digest" },
    {
      ...childAttestation.payload,
      issuedAt: new Date(
        value.context.authorization.expiresAt + 1
      ).toISOString()
    },
    {
      ...childAttestation.payload,
      claim: {
        ...childAttestation.payload.claim,
        fileByteLength: childAttestation.payload.claim.fileByteLength + 1
      }
    }
  ]) {
    const resigned = signIntegratedLiveDrillEvidence(
      Object.freeze(payload),
      value.testOnly.childLaunch.privateKeyPkcs8DerBase64,
      value.testOnly.childLaunch.publicKey
    );
    assert.throws(
      () => intentFor(value, {
        ...value.context.preCallInputs,
        consumedChildAuthorization: { attestation: resigned }
      }),
      /CHILD_AUTHORIZATION|RECOVERY_CONTINUITY_BINDING_REJECTED/u
    );
  }
});

test("source timestamp is canonicalized, fresh, and transport-only extras are rejected", (t) => {
  const value = fixture(t, "prooftoact-provider-continuity-source-");
  const source = value.context.preCallInputs.recoverySourceReceipt;
  const withDate = intentFor(value, {
    ...value.context.preCallInputs,
    recoverySourceReceipt: {
      ...source,
      recorded_at: new Date(source.recorded_at)
    }
  });
  assert.equal(
    withDate.recoverySourceReceiptSha256,
    value.context.preCallIntent.recoverySourceReceiptSha256
  );
  assert.throws(
    () => integratedLiveDrillRecoveryContinuityPreCallIntent({
      ...value.context.preCallInputs,
      recoverySourceReceipt: {
        ...source,
        recorded_at: new Date(
          value.testOnly.now - 3_601_000
        ).toISOString()
      },
      authorization: value.context.authorization,
      ledgerRootPath: value.context.ledgerRootPath,
      forbiddenRootPath: value.context.forbiddenRootPath,
      recoveryEvidenceRootPath: value.context.recoveryEvidenceRootPath,
      trustedRunContext: value.context.trustedRunContext,
      now: value.testOnly.now + 200
    }),
    /RECOVERY_CONTINUITY_BINDING_REJECTED/u
  );
  assert.throws(
    () => runIntegratedLiveDrillRecoveryContinuityW1({
      ...value.context,
      preCallInputs: {
        ...value.context.preCallInputs,
        transportSessionId: "transport-only-random-value"
      }
    }),
    /RECOVERY_CONTINUITY_BINDING_REJECTED/u
  );
});

test("mixed legacy intent and v2 journal artifacts fail closed", (t) => {
  const value = fixture(t, "prooftoact-provider-continuity-mixed-schema-");
  runIntegratedLiveDrillRecoveryContinuityW1(
    value.context
  );
  const intentPath = path.join(
    value.context.ledgerRootPath,
    `${value.context.authorization.payload.authorizationId}.` +
      "recovery-continuity-intent.json"
  );
  const persisted = JSON.parse(fs.readFileSync(intentPath, "utf8"));
  const { intentSha256: _intentSha256, ...body } = persisted;
  const legacyBody = {
    ...body,
    schemaVersion:
      "tideproof.highwater-drill-recovery-continuity-pre-call-intent.v0"
  };
  fs.writeFileSync(intentPath, `${canonicalJson({
    ...legacyBody,
    intentSha256: integratedLiveDrillCanonicalSha256(legacyBody)
  })}\n`, { mode: 0o600 });
  assert.throws(
    () => validateIntegratedLiveDrillRecoveryContinuityJournal(value.context),
    /RECOVERY_CONTINUITY_BINDING_REJECTED/u
  );
});

test("public W1-W5 reject caller-controlled journal timestamps", async (t) => {
  const value = fixture(t, "prooftoact-provider-continuity-public-clock-");
  const backdated = value.context.authorization.issuedAt + 1;
  assert.throws(
    () => runIntegratedLiveDrillRecoveryContinuityW1(
      value.context,
      { now: backdated }
    ),
    /RECOVERY_CONTINUITY_OPTIONS_REJECTED/u
  );
  await assert.rejects(
    runIntegratedLiveDrillRecoveryContinuityW2(value.context, {
      mcpCall: async () => {
        throw new Error("must not dispatch");
      },
      now: backdated
    }),
    /RECOVERY_CONTINUITY_OPTIONS_REJECTED/u
  );
  assert.throws(
    () => runIntegratedLiveDrillRecoveryContinuityW3(
      value.context,
      { now: backdated }
    ),
    /RECOVERY_CONTINUITY_OPTIONS_REJECTED/u
  );
  assert.throws(
    () => runIntegratedLiveDrillRecoveryContinuityW4(
      value.context,
      { now: backdated }
    ),
    /RECOVERY_CONTINUITY_OPTIONS_REJECTED/u
  );
  assert.throws(
    () => runIntegratedLiveDrillRecoveryContinuityW5(
      minimalW5Context(value),
      { now: backdated }
    ),
    /W5_PROVIDER_CLIENT_REJECTED/u
  );
});

test("journal rejects future-start and predated first-entry evidence", (t) => {
  const future = createRecoveryContinuityFixture(t, {
    prefix: "prooftoact-provider-continuity-future-start-",
    auditStartOffsetMs: 60_000
  });
  assert.throws(
    () => runIntegratedLiveDrillRecoveryContinuityW1(future.context),
    /RECOVERY_CONTINUITY_ORDER_REJECTED/u
  );
  assert.equal(
    fs.readdirSync(future.context.ledgerRootPath)
      .some((name) => name.includes(".01.run-intent-durable.json")),
    false
  );

  const predated = fixture(
    t,
    "prooftoact-provider-continuity-predated-entry-"
  );
  assert.throws(
    () => runIntegratedLiveDrillRecoveryContinuityW1(
      predated.context,
      { crashAfterEvent: "RUN_INTENT_DURABLE" }
    ),
    /SYNTHETIC_CRASH_RUN_INTENT_DURABLE/u
  );
  const firstEntryName = fs.readdirSync(predated.context.ledgerRootPath)
    .find((name) => name.includes(".01.run-intent-durable.json"));
  const firstEntryPath = path.join(
    predated.context.ledgerRootPath,
    firstEntryName
  );
  const firstEntry = JSON.parse(fs.readFileSync(firstEntryPath, "utf8"));
  firstEntry.recordedAt = new Date(
    Date.parse(predated.context.preCallIntent.startedAt) - 1
  ).toISOString();
  fs.writeFileSync(
    firstEntryPath,
    `${canonicalJson(firstEntry)}\n`,
    { mode: 0o600 }
  );
  assert.throws(
    () => runIntegratedLiveDrillRecoveryContinuityW1(predated.context),
    /RECOVERY_CONTINUITY_AMBIGUOUS/u
  );
});

test("post-dispatch workers record truthful post-expiry time", async (t) => {
  const originalNow = Date.now;
  t.after(() => { Date.now = originalNow; });
  const value = fixture(t, "prooftoact-provider-continuity-post-expiry-");
  runIntegratedLiveDrillRecoveryContinuityW1(value.context);
  await runIntegratedLiveDrillRecoveryContinuityW2(value.context, {
    mcpCall: async ({ logicalMcpRequestSha256 }) => ({
      logicalMcpRequestSha256,
      mcpResultSha256: "9".repeat(64),
      sessionCloseSha256: "8".repeat(64),
      sessionClosed: true
    })
  });
  const afterExpiry = value.context.authorization.expiresAt + 500;
  Date.now = () => afterExpiry;
  runIntegratedLiveDrillRecoveryContinuityW3(value.context);
  runIntegratedLiveDrillRecoveryContinuityW4(value.context);
  runIntegratedLiveDrillRecoveryContinuityW5(minimalW5Context(value));
  const receipt = validateIntegratedLiveDrillRecoveryContinuityJournal(
    value.context
  );
  assert.equal(receipt.entryCount, 17);
  const lastEntryName = fs.readdirSync(value.context.ledgerRootPath)
    .find((name) => name.includes(".17.w5-completed.json"));
  const lastEntry = JSON.parse(fs.readFileSync(
    path.join(value.context.ledgerRootPath, lastEntryName),
    "utf8"
  ));
  assert.equal(Date.parse(lastEntry.recordedAt), afterExpiry);
  assert.ok(Date.parse(lastEntry.recordedAt) >
    value.context.authorization.expiresAt);
});

test("public W2 resamples authority time before claim and dispatch", async (t) => {
  const originalNow = Date.now;
  t.after(() => { Date.now = originalNow; });

  const beforeClaim = fixture(
    t,
    "prooftoact-provider-continuity-expiry-before-claim-"
  );
  runIntegratedLiveDrillRecoveryContinuityW1(beforeClaim.context);
  Date.now = () => beforeClaim.context.authorization.expiresAt + 1;
  let calls = 0;
  await assert.rejects(
    runIntegratedLiveDrillRecoveryContinuityW2(beforeClaim.context, {
      mcpCall: async ({ logicalMcpRequestSha256 }) => {
        calls += 1;
        return {
          logicalMcpRequestSha256,
          mcpResultSha256: "9".repeat(64),
          sessionCloseSha256: "8".repeat(64),
          sessionClosed: true
        };
      }
    }),
    /AUTHORIZATION/u
  );
  assert.equal(calls, 0);

  Date.now = originalNow;
  const beforeDispatch = fixture(
    t,
    "prooftoact-provider-continuity-expiry-before-dispatch-"
  );
  runIntegratedLiveDrillRecoveryContinuityW1(beforeDispatch.context);
  const current = beforeDispatch.testOnly.now + 500;
  const clock = [
    current,
    current,
    current,
    current,
    current,
    beforeDispatch.context.authorization.expiresAt + 1
  ];
  Date.now = () => clock.length > 1 ? clock.shift() : clock[0];
  await assert.rejects(
    runIntegratedLiveDrillRecoveryContinuityW2(beforeDispatch.context, {
      mcpCall: async () => {
        calls += 1;
        throw new Error("must not dispatch");
      }
    }),
    /AUTHORIZATION/u
  );
  assert.equal(calls, 0);
});
