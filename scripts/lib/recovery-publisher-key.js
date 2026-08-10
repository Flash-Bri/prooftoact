import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign
} from "node:crypto";

import {
  RECOVERY_PUBLISHER_VERSION,
  RECOVERY_SIGNATURE_ALGORITHM,
  recoverySignaturePayloadFor
} from "../../src/cloud/recovery-store.js";
import { trustedPublisherKeysDigest } from
  "../../src/cloud/recovery-publisher-trust.js";

const TRUST_ROOT_SCHEMA = "tideproof.recovery-publisher-trust-root.v1";
const COMMITMENT_DOMAIN =
  "tideproof-recovery-publisher-trust-root-commitment-v1\n";
const KEY_ID = /^[a-z0-9][a-z0-9._:-]{0,127}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;

function fail(code, cause) {
  throw new Error(code, cause ? { cause } : undefined);
}

function canonicalBase64(value, code) {
  if (typeof value !== "string" || value === "" || value.length > 8192) {
    fail(code);
  }
  const bytes = Buffer.from(value, "base64");
  if (
    bytes.length === 0 ||
    bytes.toString("base64") !== value
  ) {
    fail(code);
  }
  return bytes;
}

function requireP256(key, code) {
  if (
    key.asymmetricKeyType !== "ec" ||
    !["prime256v1", "P-256"].includes(key.asymmetricKeyDetails?.namedCurve)
  ) {
    fail(code);
  }
  return key;
}

function parseTrustRoot(trustRootJson) {
  if (
    typeof trustRootJson !== "string" ||
    trustRootJson === "" ||
    trustRootJson.length > 16_384
  ) {
    fail("RECOVERY_PUBLISHER_TRUST_ROOT_REQUIRED");
  }
  let parsed;
  try {
    parsed = JSON.parse(trustRootJson);
  } catch (cause) {
    fail("RECOVERY_PUBLISHER_TRUST_ROOT_JSON", cause);
  }
  if (
    !parsed ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    Object.keys(parsed).sort().join("\n") !==
      ["publicKeySpkiBase64", "publisherKeyId", "schemaVersion"]
        .sort()
        .join("\n") ||
    parsed.schemaVersion !== TRUST_ROOT_SCHEMA ||
    typeof parsed.publisherKeyId !== "string" ||
    !KEY_ID.test(parsed.publisherKeyId)
  ) {
    fail("RECOVERY_PUBLISHER_TRUST_ROOT_SHAPE");
  }
  const canonical = JSON.stringify({
    schemaVersion: TRUST_ROOT_SCHEMA,
    publisherKeyId: parsed.publisherKeyId,
    publicKeySpkiBase64: parsed.publicKeySpkiBase64
  });
  if (trustRootJson !== canonical) {
    fail("RECOVERY_PUBLISHER_TRUST_ROOT_CANONICAL");
  }
  const publicKeyBytes = canonicalBase64(
    parsed.publicKeySpkiBase64,
    "RECOVERY_PUBLISHER_TRUST_ROOT_KEY"
  );
  try {
    requireP256(
      createPublicKey({
        key: publicKeyBytes,
        format: "der",
        type: "spki"
      }),
      "RECOVERY_PUBLISHER_TRUST_ROOT_KEY"
    );
  } catch (error) {
    if (error?.message === "RECOVERY_PUBLISHER_TRUST_ROOT_KEY") {
      throw error;
    }
    fail("RECOVERY_PUBLISHER_TRUST_ROOT_KEY", error);
  }
  return Object.freeze({
    publisherKeyId: parsed.publisherKeyId,
    publicKeySpkiBase64: parsed.publicKeySpkiBase64,
    canonical
  });
}

function commitmentFor(canonicalTrustRoot) {
  return createHash("sha256")
    .update(`${COMMITMENT_DOMAIN}${canonicalTrustRoot}`)
    .digest("hex");
}

export function createCommittedRecoveryPublisherSigner({
  trustRootJson,
  trustRootCommitment,
  privateKeyPkcs8Base64
} = {}) {
  const committedTrustRoot = createCommittedRecoveryPublisherTrustRoot({
    trustRootJson,
    trustRootCommitment
  });
  const trustRoot = committedTrustRoot.trustRoot;
  trustRootCommitment = committedTrustRoot.trustRootCommitment;
  const trustedPublisherKeys = committedTrustRoot.trustedPublisherKeys;
  const publisherKeySetDigest = committedTrustRoot.publisherKeySetDigest;

  const privateKeyBytes = canonicalBase64(
    privateKeyPkcs8Base64,
    "RECOVERY_PUBLISHER_PRIVATE_KEY_REQUIRED"
  );
  let privateKey;
  try {
    privateKey = requireP256(
      createPrivateKey({
        key: privateKeyBytes,
        format: "der",
        type: "pkcs8"
      }),
      "RECOVERY_PUBLISHER_PRIVATE_KEY_INVALID"
    );
  } catch (error) {
    if (error?.message === "RECOVERY_PUBLISHER_PRIVATE_KEY_INVALID") {
      throw error;
    }
    fail("RECOVERY_PUBLISHER_PRIVATE_KEY_INVALID", error);
  }
  const derivedPublicKey = createPublicKey(privateKey)
    .export({ type: "spki", format: "der" })
    .toString("base64");
  if (derivedPublicKey !== trustRoot.publicKeySpkiBase64) {
    fail("RECOVERY_PUBLISHER_SIGNING_KEY_MISMATCH");
  }

  return Object.freeze({
    publisherKeyId: trustRoot.publisherKeyId,
    publisherVersion: RECOVERY_PUBLISHER_VERSION,
    signatureAlgorithm: RECOVERY_SIGNATURE_ALGORITHM,
    publicKeySpkiBase64: trustRoot.publicKeySpkiBase64,
    trustRootCommitment,
    publisherKeySetDigest,
    trustedPublisherKeys,

    sign(input) {
      const unsigned = {
        ...input,
        publisherKeyId: trustRoot.publisherKeyId,
        publisherVersion: RECOVERY_PUBLISHER_VERSION,
        signatureAlgorithm: RECOVERY_SIGNATURE_ALGORITHM
      };
      return {
        ...unsigned,
        sourceSignatureBase64: sign(
          "sha256",
          Buffer.from(recoverySignaturePayloadFor(unsigned), "utf8"),
          privateKey
        ).toString("base64")
      };
    }
  });
}

export function createCommittedRecoveryPublisherTrustRoot({
  trustRootJson,
  trustRootCommitment
} = {}) {
  const trustRoot = parseTrustRoot(trustRootJson);
  if (
    typeof trustRootCommitment !== "string" ||
    !SHA256.test(trustRootCommitment)
  ) {
    fail("RECOVERY_PUBLISHER_TRUST_ROOT_COMMITMENT_REQUIRED");
  }
  if (commitmentFor(trustRoot.canonical) !== trustRootCommitment) {
    fail("RECOVERY_PUBLISHER_TRUST_ROOT_COMMITMENT_MISMATCH");
  }
  const trustedPublisherKeys = Object.freeze({
    [trustRoot.publisherKeyId]: trustRoot.publicKeySpkiBase64
  });
  return Object.freeze({
    schemaVersion: TRUST_ROOT_SCHEMA,
    trustRoot: Object.freeze({ ...trustRoot }),
    trustRootCommitment,
    publisherKeySetDigest: trustedPublisherKeysDigest(trustedPublisherKeys),
    trustedPublisherKeys
  });
}

export function loadCommittedRecoveryPublisherTrustRoot(
  environment = process.env
) {
  return createCommittedRecoveryPublisherTrustRoot({
    trustRootJson: environment.TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT,
    trustRootCommitment:
      environment.TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT_COMMITMENT
  });
}

export function loadCommittedRecoveryPublisherSigner(environment = process.env) {
  return createCommittedRecoveryPublisherSigner({
    trustRootJson:
      environment.TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT,
    trustRootCommitment:
      environment.TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT_COMMITMENT,
    privateKeyPkcs8Base64:
      environment.RECOVERY_PUBLISHER_PRIVATE_KEY_PKCS8_BASE64
  });
}
