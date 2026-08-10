import assert from "node:assert/strict";
import test from "node:test";

import {
  INTEGRATED_LIVE_DRILL_EVIDENCE_KEY_NAMES,
  INTEGRATED_LIVE_DRILL_CLAIM_AUTHORITY_SCHEMA,
  INTEGRATED_LIVE_DRILL_COMMITTED_RECOVERY_TRUST_ROOT_SCHEMA,
  INTEGRATED_LIVE_DRILL_CROSS_HOST_CLAIM_BLOCKER,
  INTEGRATED_LIVE_DRILL_FINALIZATION_STATEMENT_SCHEMA,
  INTEGRATED_LIVE_DRILL_HUMAN_AUTHORIZATION_TRUST_ROOT_SCHEMA,
  INTEGRATED_LIVE_DRILL_RECOVERY_FAILPOINTS,
  INTEGRATED_LIVE_DRILL_RECOVERY_WORKERS,
  INTEGRATED_LIVE_DRILL_RUN_AUTHORIZATION_SCHEMA,
  INTEGRATED_LIVE_DRILL_SPEND_AUTHORIZATION_SCHEMA,
  INTEGRATED_LIVE_DRILL_SPEND_SCOPES,
  INTEGRATED_LIVE_DRILL_TYPED_EVIDENCE,
  integratedLiveDrillAcceptanceCore,
  integratedLiveDrillAuthorizedExpectation,
  integratedLiveDrillAuthorizationLedgerRootDigest,
  integratedLiveDrillAuthorizationAttestationDigest,
  integratedLiveDrillCanonicalSha256,
  integratedLiveDrillSha256,
  integratedLiveDrillHumanAuthorizationTrustRootCommitment,
  integratedLiveDrillTypedEvidenceSubjects,
  signIntegratedLiveDrillEvidence,
  validateIntegratedLiveDrillFinalizationStatement,
  validateIntegratedLiveDrillPreAuthorizationBinding,
  validateIntegratedLiveDrillRunAuthorization,
  validateIntegratedLiveDrillTypedEvidenceAttestations
} from "../src/cloud/integrated-live-drill-authorization.js";
import {
  INTEGRATED_LIVE_DRILL_SPEC_SCHEMA,
  integratedSourceBuildIdentity
} from "../src/cloud/integrated-live-drill.js";
import {
  INTEGRATED_LIVE_DRILL_PACKET_B_BLOCKER,
  __test as finalizerTest
} from "../src/cloud/integrated-live-drill-finalizer.js";
import { trustedPublisherKeysDigest } from
  "../src/cloud/recovery-publisher-trust.js";
import {
  generateSyntheticTestOnlyEd25519Key,
  generateSyntheticTestOnlyP256PublicKey,
  syntheticTestDeploymentExpectation
} from
  "./helpers/synthetic-test-signing-keys.js";

const ISSUED_AT = "2026-08-09T16:00:00.000Z";
const EXPIRES_AT = "2026-08-09T17:00:00.000Z";
const AUTHORIZATION_ID = "11111111-1111-4111-8111-111111111111";
const STATEMENT_ID = "22222222-2222-4222-8222-222222222222";
const RUN_ID = "33333333-3333-4333-8333-333333333333";
const RACE_ID = "44444444-4444-4444-8444-444444444444";
const LEDGER_ROOT = "/private/var/prooftoact/integrated-live-drill-ledger";

function spendAuthorization() {
  return Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_SPEND_AUTHORIZATION_SCHEMA,
    currency: "USD",
    maximumCumulativeExposureUsd: "0.020000",
    scopes: INTEGRATED_LIVE_DRILL_SPEND_SCOPES.map((scope, index) =>
      Object.freeze({
        ...scope,
        maximumExposureUsd: index === 1 ? "0.020000" : "0.000000"
      }))
  });
}

function fixture() {
  const pre = generateSyntheticTestOnlyEd25519Key();
  const post = generateSyntheticTestOnlyEd25519Key();
  const alternateDenial = generateSyntheticTestOnlyEd25519Key();
  const human = generateSyntheticTestOnlyEd25519Key();
  const childLaunch = generateSyntheticTestOnlyEd25519Key();
  const humanAuthorizationTrustRoot = Object.freeze({
    schemaVersion:
      INTEGRATED_LIVE_DRILL_HUMAN_AUTHORIZATION_TRUST_ROOT_SCHEMA,
    authorityId: "PROOFTOACT_OWNER",
    custody: "HUMAN_CONTROLLED_OFFLINE",
    ...human.publicKey
  });
  const evidenceKeys = Object.fromEntries(
    INTEGRATED_LIVE_DRILL_EVIDENCE_KEY_NAMES.map((name) => [
      name,
      generateSyntheticTestOnlyEd25519Key()
    ])
  );
  const trustedPublisherKeys = Object.freeze({
    "gate1-recovery-publisher-v1":
      generateSyntheticTestOnlyP256PublicKey()
  });
  const committedTrustRoot = Object.freeze({
    schemaVersion:
      INTEGRATED_LIVE_DRILL_COMMITTED_RECOVERY_TRUST_ROOT_SCHEMA,
    trustRootCommitment: "5".repeat(64),
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
    raceId: RACE_ID,
    runId: RUN_ID,
    maximumAwsCostUsd: "0.02"
  };
  const spec = Object.freeze({
    ...specWithoutIdentity,
    sourceBuildIdentity: integratedSourceBuildIdentity(specWithoutIdentity)
  });
  const authorizationPayload = Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_RUN_AUTHORIZATION_SCHEMA,
    authorizationLedgerRootSha256:
      integratedLiveDrillAuthorizationLedgerRootDigest(LEDGER_ROOT),
    authorizationClaimAuthority: {
      schemaVersion: INTEGRATED_LIVE_DRILL_CLAIM_AUTHORITY_SCHEMA,
      authorizationLedgerRootSha256:
        integratedLiveDrillAuthorizationLedgerRootDigest(LEDGER_ROOT),
      crossHostStrongConsistencyProven: false,
      durabilityScope: "SINGLE_AUTHORITATIVE_LEDGER_ROOT",
      runnerIdentitySha256: "6".repeat(64)
    },
    authorizationId: AUTHORIZATION_ID,
    childLaunchPublicKey: childLaunch.publicKey,
    sourceCommit: spec.sourceCommit,
    treeDigest: spec.treeDigest,
    configDigest: spec.configDigest,
    runId: spec.runId,
    specSha256: integratedLiveDrillCanonicalSha256(spec),
    authorityNumericVersionArnSha256:
      integratedLiveDrillSha256(spec.functionArn),
    maximumAwsCostUsd: "0.020000",
    maximumRecoverySourceAgeSeconds: 3600,
    requiredManagedMcpToolCallCount: 1,
    requiredRecoveryJournalEntryCount: 17,
    requiredRecoveryWorkers: INTEGRATED_LIVE_DRILL_RECOVERY_WORKERS,
    requiredRecoveryFailpoints: INTEGRATED_LIVE_DRILL_RECOVERY_FAILPOINTS,
    evidencePublicKeys: Object.freeze(Object.fromEntries(
      Object.entries(evidenceKeys).map(([name, value]) => [
        name,
        value.publicKey
      ])
    )),
    expectationSha256: integratedLiveDrillCanonicalSha256(
      integratedLiveDrillAuthorizedExpectation(expectationTemplate)
    ),
    humanAuthorizationTrustRootCommitment:
      integratedLiveDrillHumanAuthorizationTrustRootCommitment(
        humanAuthorizationTrustRoot
      ),
    recoveryPublisherTrustRootCommitment:
      committedTrustRoot.trustRootCommitment,
    publisherKeySetDigest: committedTrustRoot.publisherKeySetDigest,
    spendAuthorization: spendAuthorization(),
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT
  });
  const authorizationAttestation = signIntegratedLiveDrillEvidence(
    authorizationPayload,
    human.privateKeyPkcs8DerBase64,
    human.publicKey
  );
  const expectation = Object.freeze({
    ...expectationTemplate,
    integratedLiveDrillAuthorizationAttestationSha256:
      integratedLiveDrillAuthorizationAttestationDigest(
        authorizationAttestation
      )
  });
  return {
    alternateDenial,
    authorizationAttestation,
    authorizationPayload,
    committedTrustRoot,
    evidenceKeys,
    expectation,
    human,
    humanAuthorizationTrustRoot,
    post,
    pre,
    spec
  };
}

function validateAuthorization(value, now = Date.parse(ISSUED_AT) + 1) {
  return validateIntegratedLiveDrillRunAuthorization(
    value.authorizationAttestation,
    {
      spec: value.spec,
      expectation: value.expectation,
      committedTrustRoot: value.committedTrustRoot,
      humanAuthorizationTrustRoot: value.humanAuthorizationTrustRoot,
      authorizationLedgerRootPath: LEDGER_ROOT,
      now
    }
  );
}

function resignAuthorization(value, payload) {
  const authorizationAttestation = signIntegratedLiveDrillEvidence(
    payload,
    value.human.privateKeyPkcs8DerBase64,
    value.human.publicKey
  );
  return {
    ...value,
    authorizationAttestation,
    authorizationPayload: payload,
    expectation: {
      ...value.expectation,
      integratedLiveDrillAuthorizationAttestationSha256:
        integratedLiveDrillAuthorizationAttestationDigest(
          authorizationAttestation
        )
    }
  };
}

function typedEvidenceContext(value, authorization) {
  const controlLedgerBody = {
    schemaVersion: "tideproof.highwater-drill-control-ledger-receipt.v1",
    authorizationAttestationSha256:
      integratedLiveDrillAuthorizationAttestationDigest(
        value.authorizationAttestation
      ),
    authorizationClaimSha256: "7".repeat(64),
    authorizationId: value.authorizationPayload.authorizationId,
    authorizedMaximumCumulativeExposureUsd: "0.020000",
    childLaunchDigests: ["1".repeat(64), "2".repeat(64), "3".repeat(64)],
    exactChildLaunchCount: 3,
    exactScopeCount: 3,
    reservationDigests: ["4".repeat(64), "5".repeat(64), "6".repeat(64)],
    reservedCumulativeExposureUsd: "0.020000",
    runId: value.spec.runId,
    spendAuthorizationSha256: integratedLiveDrillCanonicalSha256(
      value.authorizationPayload.spendAuthorization
    )
  };
  const controlLedgerReceipt = Object.freeze({
    ...controlLedgerBody,
    receiptSha256: integratedLiveDrillCanonicalSha256(controlLedgerBody)
  });
  const candidateBody = {
    schemaVersion: "tideproof.highwater-drill-live-candidate.v2",
    sourceCommit: value.spec.sourceCommit,
    treeDigest: value.spec.treeDigest,
    configDigest: value.spec.configDigest,
    runId: value.spec.runId,
    status: "INCOMPLETE_LIVE_GATES_PENDING",
    providerBacked: false,
    acceptance: {
      accepted: false,
      blockers: [
        INTEGRATED_LIVE_DRILL_CROSS_HOST_CLAIM_BLOCKER,
        INTEGRATED_LIVE_DRILL_PACKET_B_BLOCKER
      ],
      crashSafeRecoveryProven: false,
      deploymentAttestationBound: false,
      finalReceiptSchema: "tideproof.highwater-drill-live.v1",
      preProviderJournalPersisted: false,
      privateEvidencePersisted: false
    },
    costControl: {
      actualAwsSpendVerified: false,
      actualProviderBillingReceiptRequiredSeparately: true,
      authorizationControlLedgerReceiptSha256:
        controlLedgerReceipt.receiptSha256,
      completeProviderRequestAccounting: false,
      fixedTopLevelProviderOperationCount: true,
      operatorDeclaredMaximumAwsCostUsd: "0.02",
      providerPricingVerified: false,
      spendAuthorizationProvenByReceipt: true
    },
    privateEvidence: {
      bundleSha256: "8".repeat(64),
      currentBytesBound: true,
      sourceControlReceiptSha256: "9".repeat(64)
    },
    recovery: {
      auditsCommitted: 2,
      exactWinnerBound: true,
      managedMcpCallCount: 1,
      managedMcpRequestPayloadSha256: "b".repeat(64),
      operationalCapabilitiesReturned: false,
      restartStableSignedBundleReuseProven: false,
      signedBundleCurrentBytesBound: true,
      signedBundleSourceControlReceiptSha256: "a".repeat(64),
      unauthorizedPrincipalDenied: true
    }
  };
  const candidateReceipt = Object.freeze({
    ...candidateBody,
    receiptSha256: integratedLiveDrillCanonicalSha256(candidateBody)
  });
  const deploymentAttestationPair = Object.freeze({
    schemaVersion: "synthetic-test-only-deployment-pair"
  });
  return Object.freeze({
    authorization,
    candidateReceipt,
    controlLedgerReceipt,
    deploymentAttestationPair,
    expectation: value.expectation
  });
}

function signedTypedEvidence(value, context) {
  const subjects = integratedLiveDrillTypedEvidenceSubjects(context);
  return Object.freeze(Object.fromEntries(
    INTEGRATED_LIVE_DRILL_EVIDENCE_KEY_NAMES.map((name, index) => {
      const contract = INTEGRATED_LIVE_DRILL_TYPED_EVIDENCE[name];
      const subject = subjects[name];
      const payload = Object.freeze({
        schemaVersion: contract.schemaVersion,
        authorizationAttestationSha256:
          integratedLiveDrillAuthorizationAttestationDigest(
            value.authorizationAttestation
          ),
        authorizationId: value.authorizationPayload.authorizationId,
        candidateReceiptSha256: context.candidateReceipt.receiptSha256,
        configDigest: value.spec.configDigest,
        observedAt: new Date(
          Date.parse("2026-08-09T16:10:00.000Z") + (index * 60_000)
        ).toISOString(),
        runId: value.spec.runId,
        sourceCommit: value.spec.sourceCommit,
        status: contract.status,
        subject,
        subjectSha256: integratedLiveDrillCanonicalSha256(subject),
        treeDigest: value.spec.treeDigest
      });
      return [
        name,
        signIntegratedLiveDrillEvidence(
          payload,
          value.evidenceKeys[name].privateKeyPkcs8DerBase64,
          value.evidenceKeys[name].publicKey
        )
      ];
    })
  ));
}

test("signed integrated-live authorization binds the exact run and separated evidence keys", () => {
  const value = fixture();
  const authorization = validateAuthorization(value);
  assert.equal(authorization.payload.authorizationId, AUTHORIZATION_ID);
  assert.equal(authorization.payload.runId, RUN_ID);
  assert.equal(
    authorization.payload.evidencePublicKeys.acceptedReceipt.keyIdSha256,
    value.evidenceKeys.acceptedReceipt.publicKey.keyIdSha256
  );
});

test("integrated-live authorization rejects signature mutation, expiry, and key reuse", () => {
  const value = fixture();
  const mutated = structuredClone(value.authorizationAttestation);
  mutated.payload.maximumAwsCostUsd = "0.010000";
  assert.throws(
    () => validateIntegratedLiveDrillRunAuthorization(mutated, {
      spec: value.spec,
      expectation: value.expectation,
      committedTrustRoot: value.committedTrustRoot,
      humanAuthorizationTrustRoot: value.humanAuthorizationTrustRoot,
      authorizationLedgerRootPath: LEDGER_ROOT,
      now: Date.parse(ISSUED_AT) + 1
    }),
    /INTEGRATED_LIVE_DRILL_AUTHORIZATION_SIGNATURE_REJECTED/u
  );
  assert.throws(
    () => validateAuthorization(value, Date.parse(EXPIRES_AT) + 1),
    /INTEGRATED_LIVE_DRILL_AUTHORIZATION_TIME_REJECTED/u
  );

  const reusedKeyPayload = structuredClone(value.authorizationPayload);
  reusedKeyPayload.evidencePublicKeys.acceptedReceipt = value.pre.publicKey;
  const reusedKey = resignAuthorization(value, reusedKeyPayload);
  assert.throws(
    () => validateAuthorization(reusedKey),
    /INTEGRATED_LIVE_DRILL_AUTHORIZATION_KEY_SEPARATION_REJECTED/u
  );
  const reusedChildLaunchPayload = structuredClone(value.authorizationPayload);
  reusedChildLaunchPayload.childLaunchPublicKey = value.pre.publicKey;
  const reusedChildLaunchKey = resignAuthorization(
    value,
    reusedChildLaunchPayload
  );
  assert.throws(
    () => validateAuthorization(reusedChildLaunchKey),
    /INTEGRATED_LIVE_DRILL_AUTHORIZATION_KEY_SEPARATION_REJECTED/u
  );
});

test("integrated-live authorization rejects every expectation-to-spec drift", () => {
  for (const mutate of [
    (expectation) => { expectation.sourceCommit = "0".repeat(40); },
    (expectation) => { expectation.treeDigest = "0".repeat(40); },
    (expectation) => { expectation.configDigest = "0".repeat(64); },
    (expectation) => {
      expectation.functions.authority.numericVersionArn =
        expectation.functions.authority.numericVersionArn.replace(
          /:[0-9]+$/u,
          ":99"
        );
    }
  ]) {
    const value = fixture();
    const expectation = structuredClone(value.expectation);
    mutate(expectation);
    assert.throws(
      () => validateIntegratedLiveDrillRunAuthorization(
        value.authorizationAttestation,
        {
          spec: value.spec,
          expectation,
          committedTrustRoot: value.committedTrustRoot,
          humanAuthorizationTrustRoot: value.humanAuthorizationTrustRoot,
          authorizationLedgerRootPath: LEDGER_ROOT,
          now: Date.parse(ISSUED_AT) + 1
        }
      ),
      /(?:INTEGRATED_LIVE_DRILL_AUTHORIZATION_EXPECTATION_REJECTED|AWS_ATTEST_EXPECTATION_)/u
    );
  }
});

test("human authorization binds every deployment trust key and configuration", () => {
  const replacementKeys = [
    generateSyntheticTestOnlyEd25519Key(),
    generateSyntheticTestOnlyEd25519Key(),
    generateSyntheticTestOnlyEd25519Key()
  ];
  const mutations = [
    (expectation) => {
      expectation.receiptPublicKeys.pre =
        replacementKeys[0].publicKey.publicKeySpkiDerBase64;
    },
    (expectation) => {
      expectation.receiptPublicKeys.post =
        replacementKeys[1].publicKey.publicKeySpkiDerBase64;
    },
    (expectation) => {
      expectation.receiptPublicKeys.alternateDenial =
        replacementKeys[2].publicKey.publicKeySpkiDerBase64;
    },
    (expectation) => { expectation.configDigest = "0".repeat(64); },
    (expectation) => { expectation.sourceCommit = "0".repeat(40); },
    (expectation) => { expectation.treeDigest = "0".repeat(40); },
    (expectation) => {
      expectation.templateCanonicalDigest = "0".repeat(64);
    },
    (expectation) => {
      expectation.basis.configurationSha256 = "0".repeat(64);
    },
    (expectation) => {
      expectation.functions.authority.configurationDigest = "0".repeat(64);
    },
    (expectation) => {
      expectation.functions.authority.codeSha256 =
        Buffer.alloc(32, 9).toString("base64");
    },
    (expectation) => {
      expectation.evidenceOperator.rolePolicyDigest = "0".repeat(64);
    },
    (expectation) => {
      expectation.alternatePrincipal.rolePolicyDigest = "0".repeat(64);
    }
  ];
  for (const mutate of mutations) {
    const value = fixture();
    const expectation = structuredClone(value.expectation);
    mutate(expectation);
    assert.throws(
      () => validateIntegratedLiveDrillRunAuthorization(
        value.authorizationAttestation,
        {
          spec: value.spec,
          expectation,
          committedTrustRoot: value.committedTrustRoot,
          humanAuthorizationTrustRoot: value.humanAuthorizationTrustRoot,
          authorizationLedgerRootPath: LEDGER_ROOT,
          now: Date.parse(ISSUED_AT) + 1
        }
      ),
      /(?:INTEGRATED_LIVE_DRILL_AUTHORIZATION|AWS_ATTEST_)/u
    );
  }
});

test("authorized expectation projection rejects marker, extra, and missing-field drift", () => {
  const value = fixture();
  const projection = integratedLiveDrillAuthorizedExpectation(
    value.expectation
  );
  const markerDrift = structuredClone(projection);
  markerDrift.deploymentExpectation
    .integratedLiveDrillAuthorizationAttestationSha256 =
      "CALLER_SELECTED_MARKER";
  const markerPayload = {
    ...value.authorizationPayload,
    expectationSha256: integratedLiveDrillCanonicalSha256(markerDrift)
  };
  assert.throws(
    () => validateAuthorization(resignAuthorization(value, markerPayload)),
    /INTEGRATED_LIVE_DRILL_AUTHORIZATION_REJECTED/u
  );

  const extra = structuredClone(value.expectation);
  extra.unexpectedTrustKey = "not-authorized";
  assert.throws(
    () => integratedLiveDrillAuthorizedExpectation(extra),
    /AWS_ATTEST_EXPECTATION/u
  );
  const missing = structuredClone(value.expectation);
  delete missing.receiptPublicKeys.post;
  assert.throws(
    () => integratedLiveDrillAuthorizedExpectation(missing),
    /AWS_ATTEST_EXPECTATION_RECEIPT_KEYS/u
  );
});

test("pre-attestation must start strictly after authorization and finish before expiry", () => {
  const value = fixture();
  const authorization = validateAuthorization(value);
  const preReceipt = {
    integratedLiveDrillAuthorizationAttestationSha256:
      integratedLiveDrillAuthorizationAttestationDigest(
        value.authorizationAttestation
      ),
    observationStartedAt: "2026-08-09T16:01:00.000Z",
    observedAt: "2026-08-09T16:02:00.000Z"
  };
  assert.deepEqual(
    validateIntegratedLiveDrillPreAuthorizationBinding(
      authorization,
      preReceipt,
      { now: Date.parse("2026-08-09T16:02:01.000Z") }
    ),
    {
      preObservedAt: Date.parse(preReceipt.observedAt),
      preStartedAt: Date.parse(preReceipt.observationStartedAt)
    }
  );
  assert.throws(
    () => validateIntegratedLiveDrillPreAuthorizationBinding(
      authorization,
      { ...preReceipt, observationStartedAt: ISSUED_AT },
      { now: Date.parse("2026-08-09T16:02:01.000Z") }
    ),
    /INTEGRATED_LIVE_DRILL_AUTHORIZATION_PRE_BINDING_REJECTED/u
  );
  assert.throws(
    () => validateIntegratedLiveDrillPreAuthorizationBinding(
      authorization,
      { ...preReceipt, observedAt: "2026-08-09T17:00:00.001Z" },
      { now: Date.parse("2026-08-09T17:00:00.001Z") }
    ),
    /INTEGRATED_LIVE_DRILL_AUTHORIZATION_PRE_BINDING_REJECTED/u
  );
  assert.throws(
    () => validateIntegratedLiveDrillPreAuthorizationBinding(
      authorization,
      { ...preReceipt, observedAt: "2026-08-09T16:03:00.000Z" },
      { now: Date.parse("2026-08-09T16:02:59.999Z") }
    ),
    /INTEGRATED_LIVE_DRILL_AUTHORIZATION_PRE_BINDING_REJECTED/u
  );
});

test("typed evidence binds every signer and uses the latest safe observation", () => {
  const value = fixture();
  const authorization = validateAuthorization(value);
  const context = typedEvidenceContext(value, authorization);
  const attestations = signedTypedEvidence(value, context);
  const evidenceDigests =
    validateIntegratedLiveDrillTypedEvidenceAttestations(attestations, {
      ...context,
      now: Date.parse("2026-08-09T16:15:00.000Z")
    });
  assert.equal(
    evidenceDigests.latestObservedAt,
    Date.parse("2026-08-09T16:14:00.000Z")
  );
  for (const name of INTEGRATED_LIVE_DRILL_EVIDENCE_KEY_NAMES) {
    assert.equal(
      evidenceDigests[name],
      integratedLiveDrillCanonicalSha256(attestations[name])
    );
  }

  const subjectMutations = {
    acceptedReceipt: (subject) => {
      subject.artifact.receiptSha256 = "f".repeat(64);
    },
    billingSettlement: (subject) => {
      subject.artifact.providerBillingEvidencePresent = true;
    },
    costUpperBound: (subject) => {
      subject.artifact.maximumAwsCostUsd = "0.010000";
    },
    privateEvidence: (subject) => {
      subject.artifact.bundleSha256 = "f".repeat(64);
    },
    recoveryContinuity: (subject) => {
      subject.artifact.packetBStatus = "PASS";
    }
  };
  for (const name of INTEGRATED_LIVE_DRILL_EVIDENCE_KEY_NAMES) {
    const mutated = structuredClone(attestations);
    const subject = structuredClone(mutated[name].payload.subject);
    subjectMutations[name](subject);
    const payload = {
      ...mutated[name].payload,
      subject,
      subjectSha256: integratedLiveDrillCanonicalSha256(subject)
    };
    mutated[name] = signIntegratedLiveDrillEvidence(
      payload,
      value.evidenceKeys[name].privateKeyPkcs8DerBase64,
      value.evidenceKeys[name].publicKey
    );
    assert.throws(
      () => validateIntegratedLiveDrillTypedEvidenceAttestations(mutated, {
        ...context,
        now: Date.parse("2026-08-09T16:15:00.000Z")
      }),
      new RegExp(
        `INTEGRATED_LIVE_DRILL_${name.toUpperCase()}_ATTESTATION_REJECTED`,
        "u"
      )
    );
  }

  assert.throws(
    () => validateIntegratedLiveDrillTypedEvidenceAttestations(attestations, {
      ...context,
      now: Date.parse("2026-08-09T16:13:59.999Z")
    }),
    /INTEGRATED_LIVE_DRILL_RECOVERYCONTINUITY_ATTESTATION_TIME_REJECTED/u
  );
});

test("signed finalization binds the completed evidence and rejects mutation or premature issue", () => {
  const value = fixture();
  const authorization = validateAuthorization(value);
  const evidenceDigests = Object.freeze({
    acceptedReceipt: "0".repeat(64),
    billingSettlement: "9".repeat(64),
    costUpperBound: "1".repeat(64),
    deploymentPair: "2".repeat(64),
    latestObservedAt: Date.parse("2026-08-09T16:30:00.000Z"),
    privateEvidence: "3".repeat(64),
    recoveryContinuity: "4".repeat(64)
  });
  const candidateReceiptSha256 = "6".repeat(64);
  const payload = Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_FINALIZATION_STATEMENT_SCHEMA,
    statementId: STATEMENT_ID,
    authorizationId: AUTHORIZATION_ID,
    authorizationAttestationSha256:
      integratedLiveDrillAuthorizationAttestationDigest(
        value.authorizationAttestation
      ),
    sourceCommit: value.spec.sourceCommit,
    treeDigest: value.spec.treeDigest,
    configDigest: value.spec.configDigest,
    runId: value.spec.runId,
    candidateReceiptSha256,
    acceptedReceiptAttestationSha256: evidenceDigests.acceptedReceipt,
    billingStatus: "PENDING",
    billingSettlementAttestationSha256:
      evidenceDigests.billingSettlement,
    privateEvidenceAttestationSha256: evidenceDigests.privateEvidence,
    recoveryContinuityAttestationSha256:
      evidenceDigests.recoveryContinuity,
    costUpperBoundAttestationSha256: evidenceDigests.costUpperBound,
    deploymentAttestationPairSha256: evidenceDigests.deploymentPair,
    acceptanceCoreSha256: integratedLiveDrillCanonicalSha256(
      integratedLiveDrillAcceptanceCore({
        authorization,
        evidenceDigests,
        candidateReceiptSha256
      })
    ),
    issuedAt: "2026-08-09T16:31:00.000Z"
  });
  const attestation = signIntegratedLiveDrillEvidence(
    payload,
    value.post.privateKeyPkcs8DerBase64,
    value.post.publicKey
  );
  const finalized = validateIntegratedLiveDrillFinalizationStatement(
    attestation,
    {
      expectation: value.expectation,
      authorization,
      evidenceDigests,
      candidateReceiptSha256,
      now: Date.parse("2026-08-09T16:32:00.000Z")
    }
  );
  assert.equal(finalized.payload.statementId, STATEMENT_ID);
  const packetA = finalizerTest.packetAFinalizationDisposition({
    authorization,
    candidateReceiptSha256,
    controlLedgerReceipt: { receiptSha256: "8".repeat(64) },
    evidenceDigests,
    finalization: finalized
  });
  assert.equal(packetA.status, "PACKET_B_PROVIDER_ACCEPTANCE_PENDING");
  assert.equal(packetA.accepted, false);
  assert.equal(packetA.finalReleaseReady, false);
  assert.deepEqual(packetA.packetBBlockers, [
    INTEGRATED_LIVE_DRILL_PACKET_B_BLOCKER
  ]);
  assert.deepEqual(packetA.packetABoundaryBlockers, [
    INTEGRATED_LIVE_DRILL_CROSS_HOST_CLAIM_BLOCKER
  ]);

  const mutated = structuredClone(attestation);
  mutated.payload.candidateReceiptSha256 = "7".repeat(64);
  assert.throws(
    () => validateIntegratedLiveDrillFinalizationStatement(mutated, {
      expectation: value.expectation,
      authorization,
      evidenceDigests,
      candidateReceiptSha256,
      now: Date.parse("2026-08-09T16:32:00.000Z")
    }),
    /INTEGRATED_LIVE_DRILL_FINALIZATION_STATEMENT_SIGNATURE_REJECTED/u
  );

  const prematurePayload = {
    ...payload,
    issuedAt: "2026-08-09T16:29:59.999Z"
  };
  const premature = signIntegratedLiveDrillEvidence(
    prematurePayload,
    value.post.privateKeyPkcs8DerBase64,
    value.post.publicKey
  );
  assert.throws(
    () => validateIntegratedLiveDrillFinalizationStatement(premature, {
      expectation: value.expectation,
      authorization,
      evidenceDigests,
      candidateReceiptSha256,
      now: Date.parse("2026-08-09T16:32:00.000Z")
    }),
    /INTEGRATED_LIVE_DRILL_FINALIZATION_STATEMENT_TIME_REJECTED/u
  );

  const wrongCorePayload = {
    ...payload,
    acceptanceCoreSha256: "0".repeat(64)
  };
  const wrongCore = signIntegratedLiveDrillEvidence(
    wrongCorePayload,
    value.post.privateKeyPkcs8DerBase64,
    value.post.publicKey
  );
  assert.throws(
    () => validateIntegratedLiveDrillFinalizationStatement(wrongCore, {
      expectation: value.expectation,
      authorization,
      evidenceDigests,
      candidateReceiptSha256,
      now: Date.parse("2026-08-09T16:32:00.000Z")
    }),
    /INTEGRATED_LIVE_DRILL_FINALIZATION_STATEMENT_REJECTED/u
  );
});
