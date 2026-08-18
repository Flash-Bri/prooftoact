import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import {
  approvalSignerConstants,
  deriveProviderApprovalWindow,
  deriveProviderApprovalWindowAt,
  signProviderBrokerApproval
} from "../scripts/sign-release-provider-approval.js";
import {
  brokerPublicKeyFingerprint,
  providerBrokerConstants,
  validateProviderBrokerApproval
} from "../scripts/release-provider-one-shot-broker.js";
import { createProviderApprovalClaims } from
  "./helpers/release-provider-approval-fixture.js";

test("tracked operator public key is exact and never contains private material", () => {
  const bytes = fs.readFileSync(approvalSignerConstants.PUBLIC_KEY_PATH);
  assert.equal(
    brokerPublicKeyFingerprint(bytes),
    approvalSignerConstants.TRUSTED_PUBLIC_KEY_FINGERPRINT
  );
  assert.doesNotMatch(bytes.toString("utf8"), /PRIVATE KEY/u);
  assert.equal(path.basename(approvalSignerConstants.PUBLIC_KEY_PATH),
    "prooftoact-release-operator-public.pub");
});

test("signer accepts only the private key matching its trusted public key", () => {
  const first = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const second = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKey = first.publicKey.export({ format: "pem", type: "spki" });
  const claims = {
    approvalId: "123e4567-e89b-42d3-a456-426614174000"
  };
  assert.throws(() => signProviderBrokerApproval({
    claims,
    expiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
    privateKeyPem: second.privateKey.export({ format: "pem", type: "pkcs8" }),
    trustedPublicKeyPem: publicKey
  }), /PROVIDER_APPROVAL_SIGNER_KEY_REJECTED/u);
});

test("signer derives issuedAt from its current clock and rejects overrides", () => {
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKey = pair.publicKey.export({ format: "pem", type: "spki" });
  const privateKey = pair.privateKey.export({ format: "pem", type: "pkcs8" });
  const claims = {
    approvalId: "123e4567-e89b-42d3-a456-426614174000"
  };
  const before = Date.now();
  const expiresAt = new Date(before + 15 * 60 * 1000).toISOString();
  const window = deriveProviderApprovalWindow(expiresAt);
  const after = Date.now();
  assert.ok(Date.parse(window.issuedAt) >= before);
  assert.ok(Date.parse(window.issuedAt) <= after);
  assert.equal(window.expires, Date.parse(expiresAt));
  assert.throws(() => deriveProviderApprovalWindow(
    new Date(before - 1).toISOString()
  ), /PROVIDER_APPROVAL_SIGNER_INPUT_REJECTED/u);
  assert.throws(() => deriveProviderApprovalWindow(
    new Date(before + 60 * 60 * 1000).toISOString()
  ), /PROVIDER_APPROVAL_SIGNER_INPUT_REJECTED/u);
  assert.throws(() => signProviderBrokerApproval({
    claims,
    expiresAt,
    issuedAt: "2036-08-17T19:58:00.000Z",
    privateKeyPem: privateKey,
    trustedPublicKeyPem: publicKey
  }), /PROVIDER_APPROVAL_SIGNER_INPUT_REJECTED/u);
});

test("signer captures its system clock and validates exact window boundaries", () => {
  const issued = Date.parse("2026-08-18T17:00:00.000Z");
  assert.equal(deriveProviderApprovalWindowAt(
    "2026-08-18T17:30:00.000Z",
    issued
  ).issuedAt, "2026-08-18T17:00:00.000Z");
  for (const expiresAt of [
    "2026-08-18T17:30:00.001Z",
    "2026-08-18T17:00:00.000Z",
    "2026-08-18T16:59:59.999Z",
    "not-a-timestamp"
  ]) {
    assert.throws(() => deriveProviderApprovalWindowAt(expiresAt, issued),
      /PROVIDER_APPROVAL_SIGNER_INPUT_REJECTED/u);
  }
  assert.throws(() => deriveProviderApprovalWindowAt(
    "2026-08-18T17:15:00.000Z",
    Number.NaN
  ), /PROVIDER_APPROVAL_SIGNER_INPUT_REJECTED/u);

  const actualNow = Date.now;
  const before = actualNow();
  const expiresAt = new Date(before + 15 * 60 * 1000).toISOString();
  try {
    Date.now = () => Date.parse("2036-08-18T17:00:00.000Z");
    const window = deriveProviderApprovalWindow(expiresAt);
    assert.ok(window.issued >= before);
    assert.ok(window.issued <= actualNow());
  } finally {
    Date.now = actualNow;
  }
});

test("signer creates and immediately verifies one complete approval", () => {
  const pair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKey = pair.publicKey.export({ format: "pem", type: "spki" });
  const privateKey = pair.privateKey.export({ format: "pem", type: "pkcs8" });
  const before = Date.now();
  const expiresAt = new Date(before + 15 * 60 * 1000).toISOString();
  const claims = createProviderApprovalClaims({
    expiresAt,
    issuedAt: new Date(before).toISOString()
  });
  const envelope = signProviderBrokerApproval({
    claims,
    expiresAt,
    privateKeyPem: privateKey,
    trustedPublicKeyPem: publicKey
  });
  const after = Date.now();
  assert.ok(Date.parse(envelope.issuedAt) >= before);
  assert.ok(Date.parse(envelope.issuedAt) <= after);
  assert.equal(envelope.expiresAt, expiresAt);
  assert.equal(envelope.nonce, claims.approvalId);
  assert.deepEqual(envelope.claims, claims);
  const accepted = validateProviderBrokerApproval(
    envelope,
    publicKey,
    Date.parse(envelope.issuedAt)
  );
  assert.equal(accepted.claims.approvalId, claims.approvalId);
  assert.equal(accepted.issuedAt, Date.parse(envelope.issuedAt));
});

test("signer source hard-pins the public key and has no key-path override", () => {
  const source = fs.readFileSync(
    new URL("../scripts/sign-release-provider-approval.js", import.meta.url),
    "utf8"
  );
  assert.match(source, /9c4e4c9bdade64461547c8e511d525d8fc2e53ae0fc44642e52cf01978a08889/u);
  assert.match(source, /fd >= 3/u);
  assert.doesNotMatch(source,
    /--private-key|--public-key|--key-path|--issued-at/u);
  assert.match(source, /const SYSTEM_DATE_NOW = Date\.now\.bind\(Date\)/u);
  assert.match(source, /validateProviderBrokerApproval/u);
  assert.equal(providerBrokerConstants.OPERATOR_ISSUER,
    "NUNAN_PROOFTOACT_RELEASE_OPERATOR");
  assert.equal(typeof validateProviderBrokerApproval, "function");
});
