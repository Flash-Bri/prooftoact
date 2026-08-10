import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { Worker } from "node:worker_threads";

import {
  __test as controlLedgerTest,
  consumeIntegratedLiveDrillChildLaunch,
  consumeIntegratedLiveDrillRunAuthorization,
  finalizeIntegratedLiveDrillControlLedger,
  reserveIntegratedLiveDrillSpend
} from "../src/cloud/integrated-live-drill-control-ledger.js";
import { canonicalJson } from "../src/cloud/canonical-json.js";
import {
  INTEGRATED_LIVE_DRILL_EVIDENCE_KEY_NAMES,
  INTEGRATED_LIVE_DRILL_CLAIM_AUTHORITY_SCHEMA,
  INTEGRATED_LIVE_DRILL_COMMITTED_RECOVERY_TRUST_ROOT_SCHEMA,
  INTEGRATED_LIVE_DRILL_HUMAN_AUTHORIZATION_TRUST_ROOT_SCHEMA,
  INTEGRATED_LIVE_DRILL_RECOVERY_FAILPOINTS,
  INTEGRATED_LIVE_DRILL_RECOVERY_WORKERS,
  INTEGRATED_LIVE_DRILL_RUN_AUTHORIZATION_SCHEMA,
  INTEGRATED_LIVE_DRILL_SPEND_AUTHORIZATION_SCHEMA,
  INTEGRATED_LIVE_DRILL_SPEND_SCOPES,
  integratedLiveDrillAuthorizationAttestationDigest,
  integratedLiveDrillAuthorizationLedgerRootDigest,
  integratedLiveDrillAuthorizedExpectation,
  integratedLiveDrillCanonicalSha256,
  integratedLiveDrillHumanAuthorizationTrustRootCommitment,
  integratedLiveDrillSha256,
  signIntegratedLiveDrillEvidence
} from "../src/cloud/integrated-live-drill-authorization.js";
import {
  INTEGRATED_LIVE_DRILL_SPEC_SCHEMA,
  integratedSourceBuildIdentity
} from "../src/cloud/integrated-live-drill.js";
import { trustedPublisherKeysDigest } from
  "../src/cloud/recovery-publisher-trust.js";
import {
  generateSyntheticTestOnlyEd25519Key,
  generateSyntheticTestOnlyP256PublicKey,
  syntheticTestDeploymentExpectation
} from
  "./helpers/synthetic-test-signing-keys.js";

const NOW = Date.parse("2026-08-10T12:00:01.000Z");
const FORBIDDEN_ROOT = fs.realpathSync(process.cwd());

function secureDirectory(prefix) {
  const value = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), prefix));
  fs.chmodSync(value, 0o700);
  return fs.realpathSync(value);
}

function fixture(ledgerRootPath) {
  const pre = generateSyntheticTestOnlyEd25519Key();
  const post = generateSyntheticTestOnlyEd25519Key();
  const alternateDenial = generateSyntheticTestOnlyEd25519Key();
  const human = generateSyntheticTestOnlyEd25519Key();
  const childLaunch = generateSyntheticTestOnlyEd25519Key();
  const evidenceKeys = Object.fromEntries(
    INTEGRATED_LIVE_DRILL_EVIDENCE_KEY_NAMES.map((name) => [
      name,
      generateSyntheticTestOnlyEd25519Key()
    ])
  );
  const humanAuthorizationTrustRoot = Object.freeze({
    schemaVersion:
      INTEGRATED_LIVE_DRILL_HUMAN_AUTHORIZATION_TRUST_ROOT_SCHEMA,
    authorityId: "PROOFTOACT_OWNER",
    custody: "HUMAN_CONTROLLED_OFFLINE",
    ...human.publicKey
  });
  const trustedPublisherKeys = {
    recovery: generateSyntheticTestOnlyP256PublicKey()
  };
  const committedTrustRoot = Object.freeze({
    schemaVersion:
      INTEGRATED_LIVE_DRILL_COMMITTED_RECOVERY_TRUST_ROOT_SCHEMA,
    trustRootCommitment: "4".repeat(64),
    publisherKeySetDigest: trustedPublisherKeysDigest(trustedPublisherKeys),
    trustedPublisherKeys
  });
  const expectationTemplate = syntheticTestDeploymentExpectation({
    alternateDenialPublicKey:
      alternateDenial.publicKey.publicKeySpkiDerBase64,
    postPublicKey: post.publicKey.publicKeySpkiDerBase64,
    prePublicKey: pre.publicKey.publicKeySpkiDerBase64
  });
  const specWithoutIdentity = {
    schemaVersion: INTEGRATED_LIVE_DRILL_SPEC_SCHEMA,
    sourceCommit: expectationTemplate.sourceCommit,
    treeDigest: expectationTemplate.treeDigest,
    configDigest: expectationTemplate.configDigest,
    packageLockDigest: "d".repeat(64),
    authoritySourceDigest: "e".repeat(64),
    authorityArtifactDigest: "f".repeat(64),
    functionArn: expectationTemplate.functions.authority.numericVersionArn,
    raceId: "11111111-1111-4111-8111-111111111111",
    runId: "22222222-2222-4222-8222-222222222222",
    maximumAwsCostUsd: "0.02"
  };
  const spec = Object.freeze({
    ...specWithoutIdentity,
    sourceBuildIdentity: integratedSourceBuildIdentity(specWithoutIdentity)
  });
  const payload = Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_RUN_AUTHORIZATION_SCHEMA,
    authorizationLedgerRootSha256:
      integratedLiveDrillAuthorizationLedgerRootDigest(ledgerRootPath),
    authorizationClaimAuthority: {
      schemaVersion: INTEGRATED_LIVE_DRILL_CLAIM_AUTHORITY_SCHEMA,
      authorizationLedgerRootSha256:
        integratedLiveDrillAuthorizationLedgerRootDigest(ledgerRootPath),
      crossHostStrongConsistencyProven: false,
      durabilityScope: "SINGLE_AUTHORITATIVE_LEDGER_ROOT",
      runnerIdentitySha256: "6".repeat(64)
    },
    authorityNumericVersionArnSha256: integratedLiveDrillSha256(
      spec.functionArn
    ),
    authorizationId: "33333333-3333-4333-8333-333333333333",
    childLaunchPublicKey: childLaunch.publicKey,
    configDigest: spec.configDigest,
    evidencePublicKeys: Object.fromEntries(
      Object.entries(evidenceKeys).map(([name, key]) => [name, key.publicKey])
    ),
    expectationSha256: integratedLiveDrillCanonicalSha256(
      integratedLiveDrillAuthorizedExpectation(expectationTemplate)
    ),
    expiresAt: "2026-08-10T13:00:00.000Z",
    humanAuthorizationTrustRootCommitment:
      integratedLiveDrillHumanAuthorizationTrustRootCommitment(
        humanAuthorizationTrustRoot
      ),
    issuedAt: "2026-08-10T12:00:00.000Z",
    maximumAwsCostUsd: "0.020000",
    maximumRecoverySourceAgeSeconds: 3600,
    publisherKeySetDigest: committedTrustRoot.publisherKeySetDigest,
    recoveryPublisherTrustRootCommitment:
      committedTrustRoot.trustRootCommitment,
    requiredManagedMcpToolCallCount: 1,
    requiredRecoveryFailpoints: INTEGRATED_LIVE_DRILL_RECOVERY_FAILPOINTS,
    requiredRecoveryJournalEntryCount: 17,
    requiredRecoveryWorkers: INTEGRATED_LIVE_DRILL_RECOVERY_WORKERS,
    runId: spec.runId,
    sourceCommit: spec.sourceCommit,
    specSha256: integratedLiveDrillCanonicalSha256(spec),
    spendAuthorization: {
      schemaVersion: INTEGRATED_LIVE_DRILL_SPEND_AUTHORIZATION_SCHEMA,
      currency: "USD",
      maximumCumulativeExposureUsd: "0.020000",
      scopes: INTEGRATED_LIVE_DRILL_SPEND_SCOPES.map((scope, index) => ({
        ...scope,
        maximumExposureUsd: index === 1 ? "0.020000" : "0.000000"
      }))
    },
    treeDigest: spec.treeDigest
  });
  const attestation = signIntegratedLiveDrillEvidence(
    payload,
    human.privateKeyPkcs8DerBase64,
    human.publicKey
  );
  const expectation = Object.freeze({
    ...expectationTemplate,
    integratedLiveDrillAuthorizationAttestationSha256:
      integratedLiveDrillAuthorizationAttestationDigest(attestation),
  });
  return {
    attestation,
    committedTrustRoot,
    expectation,
    humanAuthorizationTrustRoot,
    spec
  };
}

function consume(value, ledgerRootPath) {
  return consumeIntegratedLiveDrillRunAuthorization(value.attestation, {
    spec: value.spec,
    expectation: value.expectation,
    committedTrustRoot: value.committedTrustRoot,
    humanAuthorizationTrustRoot: value.humanAuthorizationTrustRoot,
    ledgerRootPath,
    forbiddenRootPath: FORBIDDEN_ROOT,
    now: NOW
  });
}

function consumeLaunchInWorker(args) {
  const moduleUrl = new URL(
    "../src/cloud/integrated-live-drill-control-ledger.js",
    import.meta.url
  ).href;
  const source = `
    const { parentPort, workerData } = require("node:worker_threads");
    import(workerData.moduleUrl).then((module) => {
      try {
        const value = module.consumeIntegratedLiveDrillChildLaunch(
          workerData.args
        );
        parentPort.postMessage({ status: "fulfilled", value });
      } catch (error) {
        parentPort.postMessage({
          status: "rejected",
          reason: String(error && error.message)
        });
      }
    });
  `;
  return new Promise((resolve, reject) => {
    const worker = new Worker(source, {
      eval: true,
      workerData: { args, moduleUrl }
    });
    worker.once("message", resolve);
    worker.once("error", reject);
  });
}

test("authorization consumption is durable one-use across restart and concurrency", async (t) => {
  const ledgerRootPath = secureDirectory("prooftoact-auth-ledger-");
  t.after(() => fs.rmSync(ledgerRootPath, { recursive: true, force: true }));
  const value = fixture(ledgerRootPath);
  const attempts = await Promise.allSettled([
    Promise.resolve().then(() => consume(value, ledgerRootPath)),
    Promise.resolve().then(() => consume(value, ledgerRootPath))
  ]);
  assert.equal(attempts.filter(({ status }) => status === "fulfilled").length, 1);
  assert.equal(attempts.filter(({ status }) => status === "rejected").length, 1);
  assert.match(
    attempts.find(({ status }) => status === "rejected").reason.message,
    /INTEGRATED_LIVE_DRILL_AUTHORIZATION_ALREADY_CONSUMED/u
  );
  assert.throws(
    () => consume(value, ledgerRootPath),
    /INTEGRATED_LIVE_DRILL_AUTHORIZATION_ALREADY_CONSUMED/u
  );
});

test("truncated ambiguous claim remains consumed and cannot move spend", (t) => {
  const ledgerRootPath = secureDirectory("prooftoact-auth-ambiguous-");
  t.after(() => fs.rmSync(ledgerRootPath, { recursive: true, force: true }));
  const value = fixture(ledgerRootPath);
  const consumed = consume(value, ledgerRootPath);
  const [claimPath] = fs.readdirSync(ledgerRootPath)
    .filter((name) => name.endsWith("authorization-claim.json"))
    .map((name) => path.join(ledgerRootPath, name));
  fs.truncateSync(claimPath, 0);
  assert.throws(
    () => consume(value, ledgerRootPath),
    /INTEGRATED_LIVE_DRILL_AUTHORIZATION_ALREADY_CONSUMED/u
  );
  assert.throws(
    () => reserveIntegratedLiveDrillSpend({
      authorization: consumed.authorization,
      claim: consumed.claim,
      scopeId: "DVI_PROOF",
      ledgerRootPath,
      forbiddenRootPath: FORBIDDEN_ROOT,
      now: NOW + 1
    }),
    /INTEGRATED_LIVE_DRILL_AUTHORIZATION_CLAIM_AMBIGUOUS/u
  );
});

test("same-length noncanonical claim mutation cannot authorize spend", (t) => {
  const ledgerRootPath = secureDirectory("prooftoact-auth-noncanonical-");
  t.after(() => fs.rmSync(ledgerRootPath, { recursive: true, force: true }));
  const value = fixture(ledgerRootPath);
  const consumed = consume(value, ledgerRootPath);
  const [claimPath] = fs.readdirSync(ledgerRootPath)
    .filter((name) => name.endsWith("authorization-claim.json"))
    .map((name) => path.join(ledgerRootPath, name));
  const original = fs.readFileSync(claimPath);
  const parsed = JSON.parse(original.toString("utf8"));
  const reordered = Buffer.from(
    `${JSON.stringify(Object.fromEntries(Object.entries(parsed).reverse()))}\n`,
    "utf8"
  );
  assert.equal(reordered.length, original.length);
  assert.notDeepEqual(reordered, original);
  fs.writeFileSync(claimPath, reordered);
  assert.throws(
    () => reserveIntegratedLiveDrillSpend({
      authorization: consumed.authorization,
      claim: consumed.claim,
      scopeId: "DVI_PROOF",
      ledgerRootPath,
      forbiddenRootPath: FORBIDDEN_ROOT,
      now: NOW + 1
    }),
    /INTEGRATED_LIVE_DRILL_AUTHORIZATION_CLAIM_AMBIGUOUS/u
  );
});

test("fabricated prior reservation cannot unlock a later provider scope", (t) => {
  const ledgerRootPath = secureDirectory("prooftoact-spend-fabricated-");
  t.after(() => fs.rmSync(ledgerRootPath, { recursive: true, force: true }));
  const value = fixture(ledgerRootPath);
  const consumed = consume(value, ledgerRootPath);
  const firstScope = consumed.authorization.payload.spendAuthorization.scopes[0];
  const fabricated = {
    schemaVersion: "tideproof.highwater-drill-spend-reservation.v1",
    authorizationClaimSha256: "0".repeat(64),
    authorizationId: consumed.authorization.payload.authorizationId,
    cumulativeAuthorizedExposureUsd: "0.000000",
    reservedAt: new Date(NOW + 1).toISOString(),
    scope: firstScope
  };
  fs.writeFileSync(
    path.join(
      ledgerRootPath,
      controlLedgerTest.reservationFileName(
        consumed.authorization.payload.authorizationId,
        firstScope
      )
    ),
    `${canonicalJson(fabricated)}\n`,
    { mode: 0o600 }
  );
  assert.throws(
    () => reserveIntegratedLiveDrillSpend({
      authorization: consumed.authorization,
      claim: consumed.claim,
      scopeId: "AWS_AUTHORITY_RACE",
      ledgerRootPath,
      forbiddenRootPath: FORBIDDEN_ROOT,
      now: NOW + 2
    }),
    /INTEGRATED_LIVE_DRILL_SPEND_LEDGER_AMBIGUOUS/u
  );
});

test("spend ledger enforces exact order, one reservation, and cumulative cap", (t) => {
  const ledgerRootPath = secureDirectory("prooftoact-spend-ledger-");
  t.after(() => fs.rmSync(ledgerRootPath, { recursive: true, force: true }));
  const value = fixture(ledgerRootPath);
  const consumed = consume(value, ledgerRootPath);
  const args = {
    authorization: consumed.authorization,
    claim: consumed.claim,
    ledgerRootPath,
    forbiddenRootPath: FORBIDDEN_ROOT
  };
  assert.throws(
    () => reserveIntegratedLiveDrillSpend({
      ...args,
      scopeId: "AWS_AUTHORITY_RACE",
      now: NOW + 1
    }),
    /INTEGRATED_LIVE_DRILL_SPEND_RESERVATION_ORDER_REJECTED/u
  );
  const reservations = [];
  const launches = [];
  for (const [index, scope] of INTEGRATED_LIVE_DRILL_SPEND_SCOPES.entries()) {
    const reservation = reserveIntegratedLiveDrillSpend({
      ...args,
      scopeId: scope.scopeId,
      now: NOW + index + 1
    });
    reservations.push(reservation);
    launches.push(consumeIntegratedLiveDrillChildLaunch({
      ...args,
      reservation,
      tokenId: `00000000-0000-4000-8000-00000000000${index + 1}`,
      now: NOW + index + 1
    }));
  }
  assert.throws(
    () => consumeIntegratedLiveDrillChildLaunch({
      ...args,
      reservation: reservations[0],
      tokenId: "00000000-0000-4000-8000-000000000099",
      now: NOW + 5
    }),
    /INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_ALREADY_CONSUMED/u
  );
  assert.throws(
    () => reserveIntegratedLiveDrillSpend({
      ...args,
      scopeId: "MANAGED_MCP_RECOVERY",
      now: NOW + 5
    }),
    /INTEGRATED_LIVE_DRILL_SPEND_SCOPE_ALREADY_RESERVED/u
  );
  const receipt = finalizeIntegratedLiveDrillControlLedger({
    ...args,
    reservations
  });
  assert.equal(receipt.exactScopeCount, 3);
  assert.equal(receipt.exactChildLaunchCount, 3);
  assert.equal(receipt.childLaunchDigests.length, 3);
  assert.equal(launches.length, 3);
  assert.equal(receipt.reservedCumulativeExposureUsd, "0.020000");
  assert.equal(receipt.authorizedMaximumCumulativeExposureUsd, "0.020000");
  assert.match(receipt.receiptSha256, /^[0-9a-f]{64}$/u);
});

test("child launches reject reserved-but-unlaunched predecessor scopes", (t) => {
  const ledgerRootPath = secureDirectory("prooftoact-launch-order-");
  t.after(() => fs.rmSync(ledgerRootPath, { recursive: true, force: true }));
  const value = fixture(ledgerRootPath);
  const consumed = consume(value, ledgerRootPath);
  const args = {
    authorization: consumed.authorization,
    claim: consumed.claim,
    ledgerRootPath,
    forbiddenRootPath: FORBIDDEN_ROOT
  };
  const reservations = INTEGRATED_LIVE_DRILL_SPEND_SCOPES.slice(0, 2).map(
    (scope, index) => reserveIntegratedLiveDrillSpend({
      ...args,
      scopeId: scope.scopeId,
      now: NOW + index + 1
    })
  );
  assert.throws(
    () => consumeIntegratedLiveDrillChildLaunch({
      ...args,
      reservation: reservations[1],
      tokenId: "00000000-0000-4000-8000-000000000012",
      now: NOW + 3
    }),
    /INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_ORDER_REJECTED/u
  );
  consumeIntegratedLiveDrillChildLaunch({
    ...args,
    reservation: reservations[0],
    tokenId: "00000000-0000-4000-8000-000000000011",
    now: NOW + 3
  });
  assert.equal(
    consumeIntegratedLiveDrillChildLaunch({
      ...args,
      reservation: reservations[1],
      tokenId: "00000000-0000-4000-8000-000000000012",
      now: NOW + 4
    }).sequence,
    2
  );
});

test("concurrent later-scope launches cannot bypass an unlaunched first scope", async (t) => {
  const ledgerRootPath = secureDirectory("prooftoact-launch-concurrent-");
  t.after(() => fs.rmSync(ledgerRootPath, { recursive: true, force: true }));
  const value = fixture(ledgerRootPath);
  const consumed = consume(value, ledgerRootPath);
  const args = {
    authorization: consumed.authorization,
    claim: consumed.claim,
    ledgerRootPath,
    forbiddenRootPath: FORBIDDEN_ROOT
  };
  const reservations = INTEGRATED_LIVE_DRILL_SPEND_SCOPES.map(
    (scope, index) => reserveIntegratedLiveDrillSpend({
      ...args,
      scopeId: scope.scopeId,
      now: NOW + index + 1
    })
  );
  const attempts = await Promise.all([
    consumeLaunchInWorker({
      ...args,
      reservation: reservations[1],
      tokenId: "00000000-0000-4000-8000-000000000022",
      now: NOW + 4
    }),
    consumeLaunchInWorker({
      ...args,
      reservation: reservations[2],
      tokenId: "00000000-0000-4000-8000-000000000023",
      now: NOW + 4
    })
  ]);
  assert.deepEqual(
    attempts.map(({ status }) => status),
    ["rejected", "rejected"]
  );
  for (const attempt of attempts) {
    assert.match(
      attempt.reason,
      /INTEGRATED_LIVE_DRILL_CHILD_LAUNCH_ORDER_REJECTED/u
    );
  }
  assert.equal(
    fs.readdirSync(ledgerRootPath)
      .filter((name) => name.endsWith("child-launch.json")).length,
    0
  );
});
