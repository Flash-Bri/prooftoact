import { generateKeyPairSync, sign } from "node:crypto";
import {
  RECOVERY_PUBLISHER_VERSION,
  RECOVERY_SIGNATURE_ALGORITHM,
  recoverySignaturePayloadFor
} from "../../src/cloud/recovery-store.js";

const DEFAULT_KEY_ID = "gate1-synthetic-recovery-publisher-p256-v1";

export function createSyntheticRecoverySigner({
  publisherKeyId = DEFAULT_KEY_ID
} = {}) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256"
  });
  const publicKeySpkiBase64 = publicKey
    .export({ type: "spki", format: "der" })
    .toString("base64");

  return {
    publisherKeyId,
    publisherVersion: RECOVERY_PUBLISHER_VERSION,
    signatureAlgorithm: RECOVERY_SIGNATURE_ALGORITHM,
    publicKeySpkiBase64,

    sign(input) {
      const unsigned = {
        ...input,
        publisherKeyId,
        publisherVersion: RECOVERY_PUBLISHER_VERSION,
        signatureAlgorithm: RECOVERY_SIGNATURE_ALGORITHM
      };
      const sourceSignatureBase64 = sign(
        "sha256",
        Buffer.from(recoverySignaturePayloadFor(unsigned), "utf8"),
        privateKey
      ).toString("base64");
      return {
        ...unsigned,
        sourceSignatureBase64
      };
    }
  };
}
