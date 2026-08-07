import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_RECEIPT_SCHEMA,
  INTEGRATED_LIVE_DRILL_SPEC_SCHEMA,
  integratedSourceBuildIdentity,
  persistOrReuseIntegratedLiveDrillRecoveryBundle
} from "../src/cloud/integrated-live-drill.js";
import { normalizedRecoveryBundleFor } from
  "../src/cloud/recovery-store.js";
import { createSyntheticRecoverySigner } from
  "../scripts/lib/synthetic-recovery-signer.js";

const runId = "11111111-1111-4111-8111-111111111111";
const specWithoutIdentity = {
  schemaVersion: INTEGRATED_LIVE_DRILL_SPEC_SCHEMA,
  sourceCommit: "a".repeat(40),
  treeDigest: "b".repeat(40),
  configDigest: "c".repeat(64),
  packageLockDigest: "d".repeat(64),
  authoritySourceDigest: "e".repeat(64),
  authorityArtifactDigest: "f".repeat(64),
  functionArn:
    "arn:aws:lambda:us-east-1:111111111111:function:prooftoact-authority:7",
  raceId: "22222222-2222-4222-8222-222222222222",
  runId,
  maximumAwsCostUsd: "0.02"
};
const spec = Object.freeze({
  ...specWithoutIdentity,
  sourceBuildIdentity: integratedSourceBuildIdentity(specWithoutIdentity)
});
const unsignedBundle = Object.freeze({
  tenantId: "33333333-3333-4333-8333-333333333333",
  recoverySessionId: "44444444-4444-4444-8444-444444444444",
  subjectBindingHash: "1".repeat(64),
  schemaVersion: 2,
  snapshotVersion: 1,
  sourceClusterId: "55555555-5555-4555-8555-555555555555",
  sourceCommitTs: "2026-08-07T12:00:00.000Z",
  sourceDigest: "2".repeat(64),
  policyVersion: "gate1-policy-v2",
  checkpointSummary: {
    checkpointVersion: 1,
    failedAgent: "synthetic-agent-a",
    phase: "successor-context-recovery",
    scenario: "synthetic-highwater"
  },
  evidenceSummary: {
    admittedCount: 1,
    classification: "synthetic",
    evidenceDigest: "3".repeat(64)
  },
  conflictSummary: { status: "none", unresolvedCount: 0 },
  receiptSummary: {
    durableIntentPresent: true,
    outcome: "resource_reserved",
    reason: null,
    resourceLabel: "synthetic-resource"
  },
  expiresAt: "2026-08-08T12:00:00.000Z"
});

function privateDirectory() {
  const directory = fs.mkdtempSync(
    path.join(fs.realpathSync(os.tmpdir()), "prooftoact-signed-bundle-")
  );
  fs.chmodSync(directory, 0o700);
  return fs.realpathSync(directory);
}

test("signed recovery bundle survives restart with the exact first signature bytes", () => {
  const directory = privateDirectory();
  const destinationPath = path.join(
    directory,
    `${runId}.signed-recovery-bundle.json`
  );
  const signer = createSyntheticRecoverySigner();
  const trustedPublisherKeys = {
    [signer.publisherKeyId]: signer.publicKeySpkiBase64
  };
  const firstCandidate = signer.sign(unsignedBundle);
  const restartCandidate = signer.sign(unsignedBundle);
  assert.notEqual(
    firstCandidate.sourceSignatureBase64,
    restartCandidate.sourceSignatureBase64
  );
  try {
    const first = persistOrReuseIntegratedLiveDrillRecoveryBundle({
      destinationPath,
      evidenceRootPath: directory,
      forbiddenRootPath: fs.realpathSync(process.cwd()),
      spec,
      signedBundle: firstCandidate,
      trustedPublisherKeys
    });
    const restarted = persistOrReuseIntegratedLiveDrillRecoveryBundle({
      destinationPath,
      evidenceRootPath: directory,
      forbiddenRootPath: fs.realpathSync(process.cwd()),
      spec,
      signedBundle: restartCandidate,
      trustedPublisherKeys
    });
    const normalizedFirst = normalizedRecoveryBundleFor(firstCandidate);

    assert.equal(
      first.receipt.schemaVersion,
      INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_RECEIPT_SCHEMA
    );
    assert.equal(first.receipt.reusedExisting, false);
    assert.equal(restarted.receipt.reusedExisting, true);
    assert.deepEqual(first.bundle, normalizedFirst);
    assert.deepEqual(restarted.bundle, normalizedFirst);
    assert.equal(
      restarted.receipt.signedBundleSha256,
      first.receipt.signedBundleSha256
    );
    assert.equal(
      restarted.receipt.signatureDigest,
      normalizedFirst.signatureDigest
    );
    assert.equal(fs.statSync(destinationPath).mode & 0o777, 0o600);
    assert.equal(first.receipt.atomicCreateOnly, true);
    assert.equal(first.receipt.directoryEntrySynced, true);
    assert.equal(first.receipt.rereadVerified, true);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("persisted signed recovery bundle rejects tamper and changed canonical input", () => {
  const directory = privateDirectory();
  const destinationPath = path.join(
    directory,
    `${runId}.signed-recovery-bundle.json`
  );
  const signer = createSyntheticRecoverySigner();
  const trustedPublisherKeys = {
    [signer.publisherKeyId]: signer.publicKeySpkiBase64
  };
  const argumentsFor = (signedBundle) => ({
    destinationPath,
    evidenceRootPath: directory,
    forbiddenRootPath: fs.realpathSync(process.cwd()),
    spec,
    signedBundle,
    trustedPublisherKeys
  });
  try {
    persistOrReuseIntegratedLiveDrillRecoveryBundle(
      argumentsFor(signer.sign(unsignedBundle))
    );
    assert.throws(
      () => persistOrReuseIntegratedLiveDrillRecoveryBundle(
        argumentsFor(signer.sign({
          ...unsignedBundle,
          sourceDigest: "9".repeat(64)
        }))
      ),
      /INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_MISMATCH/u
    );
    fs.appendFileSync(destinationPath, " ");
    assert.throws(
      () => persistOrReuseIntegratedLiveDrillRecoveryBundle(
        argumentsFor(signer.sign(unsignedBundle))
      ),
      /INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_REJECTED/u
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
