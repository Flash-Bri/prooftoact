import assert from "node:assert/strict";
import test from "node:test";

import { canonicalJson } from "../src/cloud/canonical-json.js";
import {
  INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_SCHEMA,
  INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_ENVIRONMENT,
  assertIntegratedLiveDrillChildAuthorizationCurrent,
  integratedLiveDrillChildAuthorizationContext,
  parseIntegratedLiveDrillChildAuthorization
} from "../src/cloud/integrated-live-drill-child-authorization.js";
import {
  INTEGRATED_LIVE_DRILL_SPEND_RESERVATION_SCHEMA
} from
  "../src/cloud/integrated-live-drill-control-ledger.js";
import {
  INTEGRATED_LIVE_DRILL_SPEND_SCOPES,
  integratedLiveDrillCanonicalSha256,
  verifyIntegratedLiveDrillEvidence
} from "../src/cloud/integrated-live-drill-authorization.js";
import { generateSyntheticTestOnlyEd25519Key } from
  "./helpers/synthetic-test-signing-keys.js";

const NOW = Date.parse("2026-08-10T12:00:00.000Z");

function fixture() {
  const childLaunch = generateSyntheticTestOnlyEd25519Key();
  const spec = Object.freeze({ value: "synthetic-spec" });
  const expectation = Object.freeze({ value: "synthetic-expectation" });
  const authorization = {
    attestation: {
      payload: { value: "synthetic" },
      schemaVersion: "synthetic",
      signature: { value: "synthetic" }
    },
    payload: {
      authorizationId: "11111111-1111-4111-8111-111111111111",
      authorizationClaimAuthority: {
        runnerIdentitySha256: "8".repeat(64)
      },
      childLaunchPublicKey: childLaunch.publicKey,
      configDigest: "f".repeat(64),
      expiresAt: "2026-08-10T13:00:00.000Z",
      issuedAt: "2026-08-10T12:00:00.000Z",
      runId: "22222222-2222-4222-8222-222222222222",
      sourceCommit: "1".repeat(40),
      specSha256: integratedLiveDrillCanonicalSha256(spec),
      spendAuthorization: {
        scopes: INTEGRATED_LIVE_DRILL_SPEND_SCOPES.map((scope, index) => ({
          ...scope,
          maximumExposureUsd: index === 1 ? "0.020000" : "0.000000"
        }))
      },
      treeDigest: "2".repeat(40)
    },
    issuedAt: NOW,
    expiresAt: Date.parse("2026-08-10T13:00:00.000Z")
  };
  const claim = {
    schemaVersion: "tideproof.highwater-drill-authorization-claim.v1",
    authorizationClaimSha256: "a".repeat(64),
    authorizationId: authorization.payload.authorizationId,
    fileByteLength: 512,
    fileNameSha256: "b".repeat(64),
    spendAuthorizationSha256: "c".repeat(64)
  };
  const reservation = {
    schemaVersion: INTEGRATED_LIVE_DRILL_SPEND_RESERVATION_SCHEMA,
    authorizationId: authorization.payload.authorizationId,
    cumulativeAuthorizedExposureUsd: "0.000000",
    fileByteLength: 512,
    fileNameSha256: "d".repeat(64),
    reservationSha256: "e".repeat(64),
    scopeId: "DVI_PROOF",
    sequence: 1
  };
  return {
    authorization,
    claim,
    expectation,
    privateKeyPkcs8DerBase64: childLaunch.privateKeyPkcs8DerBase64,
    reservation,
    spec,
    now: NOW,
    nonceSha256: "9".repeat(64),
    tokenId: "33333333-3333-4333-8333-333333333333"
  };
}

test("child context binds one reserved provider scope and authorization deadline", () => {
  const value = fixture();
  const context = integratedLiveDrillChildAuthorizationContext(value);
  assert.equal(
    verifyIntegratedLiveDrillEvidence(
      context,
      value.authorization.payload.childLaunchPublicKey,
      INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_SCHEMA,
      "TEST_CHILD_SIGNATURE_REJECTED"
    ).schemaVersion,
    INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_SCHEMA
  );
  const parsed = parseIntegratedLiveDrillChildAuthorization(
    {
      [INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_ENVIRONMENT]:
        canonicalJson(context)
    },
    "DVI_PROOF",
    { now: NOW }
  );
  assert.equal(parsed.value.scope.scopeId, "DVI_PROOF");
  assert.equal(parsed.value.scope.sequence, 1);
  assert.equal(parsed.expiresAt, Date.parse(context.payload.expiresAt));
  assert.equal(
    assertIntegratedLiveDrillChildAuthorizationCurrent(parsed, { now: NOW }),
    parsed
  );
});

test("child context rejects scope substitution, noncanonical input, and expiry", () => {
  const context = integratedLiveDrillChildAuthorizationContext(fixture());
  const canonical = canonicalJson(context);
  assert.throws(
    () => parseIntegratedLiveDrillChildAuthorization(
      { [INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_ENVIRONMENT]: canonical },
      "AWS_AUTHORITY_RACE",
      { now: NOW }
    ),
    /INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_REJECTED/u
  );
  assert.throws(
    () => parseIntegratedLiveDrillChildAuthorization(
      {
        [INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_ENVIRONMENT]:
          JSON.stringify(context, null, 2)
      },
      "DVI_PROOF",
      { now: NOW }
    ),
    /INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_REJECTED/u
  );
  assert.throws(
    () => parseIntegratedLiveDrillChildAuthorization(
      { [INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_ENVIRONMENT]: canonical },
      "DVI_PROOF",
    { now: Date.parse(context.payload.expiresAt) + 1 }
    ),
    /INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_REJECTED/u
  );
  const parsed = parseIntegratedLiveDrillChildAuthorization(
    { [INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_ENVIRONMENT]: canonical },
    "DVI_PROOF",
    { now: NOW }
  );
  assert.throws(
    () => assertIntegratedLiveDrillChildAuthorizationCurrent(parsed, {
      now: Date.parse(context.payload.expiresAt) + 1
    }),
    /INTEGRATED_LIVE_DRILL_CHILD_AUTHORIZATION_TIME_REJECTED/u
  );
});
