import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey } from "node:crypto";
import test from "node:test";

import {
  deriveFreshRecoveryPublisherSecret,
  freshRecoveryPublisherSecretBytes,
  generateFreshRecoveryPublisherSecret,
  validateFreshRecoveryPublisherSecret
} from "../scripts/lib/fresh-recovery-publisher-key.js";

const BINDING = Object.freeze({
  operationId: "123e4567-e89b-42d3-a456-426614174000",
  sourceCommit: "a".repeat(40),
  treeDigest: "b".repeat(40)
});

test("fresh recovery signer is one source-bound P-256 secret", () => {
  const value = generateFreshRecoveryPublisherSecret(BINDING);
  assert.equal(value.publisherKeyId,
    `prooftoact-gate2-${BINDING.operationId}`);
  assert.match(value.trustRootCommitment, /^[0-9a-f]{64}$/u);
  assert.match(value.publisherKeySetDigest, /^[0-9a-f]{64}$/u);
  assert.match(value.secretBytesSha256, /^[0-9a-f]{64}$/u);
  const privateKey = createPrivateKey({
    key: Buffer.from(value.privateKeyPkcs8Base64, "base64"),
    format: "der",
    type: "pkcs8"
  });
  assert.equal(privateKey.asymmetricKeyType, "ec");
  assert.equal(privateKey.asymmetricKeyDetails.namedCurve, "prime256v1");
  const root = JSON.parse(value.trustRootJson);
  assert.equal(createPublicKey(privateKey)
    .export({ type: "spki", format: "der" })
    .toString("base64"), root.publicKeySpkiBase64);
  const bytes = freshRecoveryPublisherSecretBytes(value, BINDING);
  assert.equal(bytes.at(-1), 0x0a);
  assert.equal(bytes.includes(Buffer.from("secretBytesSha256")), false);
});

test("fresh recovery signer rejects source, commitment, and private-key drift", () => {
  const value = generateFreshRecoveryPublisherSecret(BINDING);
  assert.throws(() => validateFreshRecoveryPublisherSecret(value, {
    ...BINDING,
    sourceCommit: "c".repeat(40)
  }), /FRESH_RECOVERY_PUBLISHER_SECRET_REJECTED/u);
  assert.throws(() => validateFreshRecoveryPublisherSecret({
    ...value,
    trustRootCommitment: "0".repeat(64),
    secretBytesSha256: undefined,
    trustRootJsonSha256: undefined
  }, BINDING), /FRESH_RECOVERY_PUBLISHER_SECRET_REJECTED/u);
  const changed = generateFreshRecoveryPublisherSecret(BINDING);
  const unsigned = { ...value };
  delete unsigned.secretBytesSha256;
  delete unsigned.trustRootJsonSha256;
  unsigned.privateKeyPkcs8Base64 = changed.privateKeyPkcs8Base64;
  assert.throws(() => validateFreshRecoveryPublisherSecret(unsigned, BINDING),
    /FRESH_RECOVERY_PUBLISHER_SECRET_REJECTED/u);
});

test("fresh recovery signer deterministically converges from sealed key material", () => {
  const keyMaterial = Buffer.from("k".repeat(64), "utf8");
  const first = deriveFreshRecoveryPublisherSecret(BINDING, keyMaterial);
  const second = deriveFreshRecoveryPublisherSecret(
    BINDING,
    Buffer.from(keyMaterial)
  );
  assert.equal(first.secretBytesSha256, second.secretBytesSha256);
  assert.equal(first.privateKeyPkcs8Base64, second.privateKeyPkcs8Base64);
  assert.equal(first.trustRootCommitment, second.trustRootCommitment);
  const changed = deriveFreshRecoveryPublisherSecret(
    BINDING,
    Buffer.from("m".repeat(64), "utf8")
  );
  assert.notEqual(first.secretBytesSha256, changed.secretBytesSha256);
});
