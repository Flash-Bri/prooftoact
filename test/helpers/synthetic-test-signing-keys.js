import { createHash, generateKeyPairSync } from "node:crypto";
import fs from "node:fs";

// SYNTHETIC TEST-ONLY KEY MATERIAL. These process-local keys are generated only
// inside Node's test runner. They are not operator, deployment, provider, or
// spend-authority roots and must never be loaded by runtime source.

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function generateSyntheticTestOnlyEd25519Key() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeyBytes = publicKey.export({ format: "der", type: "spki" });
  return Object.freeze({
    privateKeyPkcs8DerBase64: privateKey
      .export({ format: "der", type: "pkcs8" })
      .toString("base64"),
    privateKeyPkcs8Pem: privateKey.export({ format: "pem", type: "pkcs8" }),
    publicKey: Object.freeze({
      keyIdSha256: sha256(publicKeyBytes),
      publicKeySpkiDerBase64: publicKeyBytes.toString("base64")
    })
  });
}

export function generateSyntheticTestOnlyP256PublicKey() {
  const { publicKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256"
  });
  return publicKey
    .export({ format: "der", type: "spki" })
    .toString("base64");
}

export function syntheticTestDeploymentExpectation({
  alternateDenialPublicKey,
  authorizationAttestationSha256 = "0".repeat(64),
  postPublicKey,
  prePublicKey
}) {
  const fixture = JSON.parse(fs.readFileSync(new URL(
    "../fixtures/integrated-live-drill-pre-attestation.json",
    import.meta.url
  ), "utf8"));
  return {
    ...fixture.expectation,
    integratedLiveDrillAuthorizationAttestationSha256:
      authorizationAttestationSha256,
    receiptPublicKeys: {
      alternateDenial: alternateDenialPublicKey,
      post: postPublicKey,
      pre: prePublicKey
    }
  };
}
