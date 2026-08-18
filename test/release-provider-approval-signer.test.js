import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import {
  approvalSignerConstants,
  signProviderBrokerApproval
} from "../scripts/sign-release-provider-approval.js";
import {
  brokerPublicKeyFingerprint,
  providerBrokerConstants,
  validateProviderBrokerApproval
} from "../scripts/release-provider-one-shot-broker.js";

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
    expiresAt: "2026-08-17T20:28:00.000Z",
    issuedAt: "2026-08-17T19:58:00.000Z",
    privateKeyPem: second.privateKey.export({ format: "pem", type: "pkcs8" }),
    trustedPublicKeyPem: publicKey
  }), /PROVIDER_APPROVAL_SIGNER_KEY_REJECTED/u);
});

test("signer source hard-pins the public key and has no key-path override", () => {
  const source = fs.readFileSync(
    new URL("../scripts/sign-release-provider-approval.js", import.meta.url),
    "utf8"
  );
  assert.match(source, /9c4e4c9bdade64461547c8e511d525d8fc2e53ae0fc44642e52cf01978a08889/u);
  assert.match(source, /fd >= 3/u);
  assert.doesNotMatch(source, /--private-key|--public-key|--key-path/u);
  assert.match(source, /validateProviderBrokerApproval/u);
  assert.equal(providerBrokerConstants.OPERATOR_ISSUER,
    "NUNAN_PROOFTOACT_RELEASE_OPERATOR");
  assert.equal(typeof validateProviderBrokerApproval, "function");
});
