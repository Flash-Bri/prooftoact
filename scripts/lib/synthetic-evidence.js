import { generateKeyPairSync, sign } from "node:crypto";
import { signedEvidencePayloadFor } from "../../src/cloud/authority-store.js";

const DEFAULT_ISSUER = "synthetic-county-sensor";
const DEFAULT_KEY_ID = "gate1-synthetic-ed25519-v1";
const DEFAULT_VERIFIER_VERSION = "gate1-ed25519-verifier-v1";

export function createSyntheticEvidenceSigner({
  issuer = DEFAULT_ISSUER,
  verificationKeyId = DEFAULT_KEY_ID,
  verifierVersion = DEFAULT_VERIFIER_VERSION
} = {}) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeySpkiBase64 = publicKey
    .export({ type: "spki", format: "der" })
    .toString("base64");

  return {
    issuer,
    verificationKeyId,
    verifierVersion,

    async register(store, tenantId) {
      return store.registerVerificationKey({
        tenantId,
        verificationKeyId,
        issuer,
        algorithm: "ed25519",
        publicKeySpkiBase64,
        validFrom: new Date(Date.now() - 24 * 60 * 60 * 1_000).toISOString(),
        validUntil: new Date(
          Date.now() + 30 * 24 * 60 * 60 * 1_000
        ).toISOString()
      });
    },

    async append(store, input) {
      if ((input.issuer ?? issuer) !== issuer) {
        throw new Error("synthetic signer issuer mismatch");
      }
      const evidence = { ...input, issuer };
      const signatureBase64 = sign(
        null,
        Buffer.from(signedEvidencePayloadFor(evidence), "utf8"),
        privateKey
      ).toString("base64");
      return store.appendSignedEvidence({
        ...evidence,
        verificationKeyId,
        verifierVersion,
        signatureBase64
      });
    },

    sign(input) {
      const evidence = { ...input, issuer: input.issuer ?? issuer };
      return sign(
        null,
        Buffer.from(signedEvidencePayloadFor(evidence), "utf8"),
        privateKey
      ).toString("base64");
    }
  };
}
