import {
  createECDH,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync
} from "node:crypto";

const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const SECRET_SCHEMA = "prooftoact.fresh-recovery-publisher-secret.v1";
const TRUST_ROOT_SCHEMA = "tideproof.recovery-publisher-trust-root.v1";
const COMMITMENT_DOMAIN =
  "tideproof-recovery-publisher-trust-root-commitment-v1\n";
const DERIVATION_DOMAIN =
  "prooftoact-fresh-recovery-publisher-deterministic-v1\n";
const P256_ORDER = BigInt(
  "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
);

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, expected) {
  return plainObject(value) &&
    Object.keys(value).sort().join("\n") === [...expected].sort().join("\n");
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (plainObject(value)) {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function canonicalBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, "utf8");
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalBase64(value, code) {
  requireCondition(typeof value === "string" && value.length > 0 &&
    value.length <= 8192, code);
  const bytes = Buffer.from(value, "base64");
  requireCondition(bytes.length > 0 && bytes.toString("base64") === value,
    code);
  return bytes;
}

function trustRootJsonFor(publisherKeyId, publicKeySpkiBase64) {
  // This byte order is the existing recovery verifier's exact canonical
  // contract. It is stored as a string inside the JCS-sorted secret envelope.
  return JSON.stringify({
    schemaVersion: TRUST_ROOT_SCHEMA,
    publisherKeyId,
    publicKeySpkiBase64
  });
}

function validateTrustRoot(trustRootJson, trustRootCommitment, code) {
  let root;
  try {
    root = JSON.parse(trustRootJson);
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(exactKeys(root, [
    "publicKeySpkiBase64", "publisherKeyId", "schemaVersion"
  ]) && root.schemaVersion === TRUST_ROOT_SCHEMA &&
    /^[a-z0-9][a-z0-9._:-]{0,127}$/u.test(root.publisherKeyId ?? "") &&
    trustRootJson === trustRootJsonFor(
      root.publisherKeyId,
      root.publicKeySpkiBase64
    ) && sha256(Buffer.from(`${COMMITMENT_DOMAIN}${trustRootJson}`, "utf8")) ===
      trustRootCommitment, code);
  const publicKeyBytes = canonicalBase64(root.publicKeySpkiBase64, code);
  let publicKey;
  try {
    publicKey = createPublicKey({
      key: publicKeyBytes,
      format: "der",
      type: "spki"
    });
  } catch (cause) {
    reject(code, cause);
  } finally {
    publicKeyBytes.fill(0);
  }
  requireCondition(publicKey.asymmetricKeyType === "ec" &&
    ["prime256v1", "P-256"].includes(
      publicKey.asymmetricKeyDetails?.namedCurve
    ), code);
  const publisherKeySetDigest = sha256(Buffer.from(canonicalJson([{
    keyId: root.publisherKeyId,
    publicKeyDigest: sha256(Buffer.from(root.publicKeySpkiBase64, "base64"))
  }]), "utf8"));
  return { root, publicKey, publisherKeySetDigest };
}

function validateBinding(value, code) {
  requireCondition(exactKeys(value, [
    "operationId", "sourceCommit", "treeDigest"
  ]) && UUID.test(value.operationId ?? "") &&
    HEX_40.test(value.sourceCommit ?? "") && HEX_40.test(value.treeDigest ?? ""),
  code);
  return value;
}

export function validateFreshRecoveryPublisherSecret(value, binding) {
  const code = "FRESH_RECOVERY_PUBLISHER_SECRET_REJECTED";
  validateBinding(binding, code);
  requireCondition(exactKeys(value, [
    "operationId",
    "privateKeyPkcs8Base64",
    "publisherKeyId",
    "publisherKeySetDigest",
    "schemaVersion",
    "sourceCommit",
    "treeDigest",
    "trustRootCommitment",
    "trustRootJson"
  ]) && value.schemaVersion === SECRET_SCHEMA &&
    value.operationId === binding.operationId &&
    value.sourceCommit === binding.sourceCommit &&
    value.treeDigest === binding.treeDigest &&
    value.publisherKeyId === `prooftoact-gate2-${binding.operationId}` &&
    HEX_64.test(value.publisherKeySetDigest ?? "") &&
    HEX_64.test(value.trustRootCommitment ?? ""), code);
  canonicalBase64(value.privateKeyPkcs8Base64, code).fill(0);
  const committed = validateTrustRoot(
    value.trustRootJson,
    value.trustRootCommitment,
    code
  );
  requireCondition(committed.root.publisherKeyId === value.publisherKeyId &&
    committed.publisherKeySetDigest === value.publisherKeySetDigest, code);
  const privateKeyBytes = canonicalBase64(value.privateKeyPkcs8Base64, code);
  let privateKey;
  try {
    privateKey = createPrivateKey({
      key: privateKeyBytes,
      format: "der",
      type: "pkcs8"
    });
  } catch (cause) {
    reject(code, cause);
  } finally {
    privateKeyBytes.fill(0);
  }
  requireCondition(privateKey.asymmetricKeyType === "ec" &&
    ["prime256v1", "P-256"].includes(
      privateKey.asymmetricKeyDetails?.namedCurve
    ) && createPublicKey(privateKey)
      .export({ type: "spki", format: "der" })
      .toString("base64") === committed.root.publicKeySpkiBase64, code);
  const secretBytes = canonicalBytes(value);
  requireCondition(secretBytes.length > 0 && secretBytes.length <= 32 * 1024,
    code);
  return Object.freeze({
    ...value,
    secretBytesSha256: sha256(secretBytes),
    trustRootJsonSha256: sha256(Buffer.from(value.trustRootJson, "utf8"))
  });
}

function publisherSecretFromDer(binding, privateKey, publicKey, code) {
  const publisherKeyId = `prooftoact-gate2-${binding.operationId}`;
  const trustRootJson = trustRootJsonFor(
    publisherKeyId,
    publicKey.toString("base64")
  );
  const trustRootCommitment = sha256(Buffer.from(
    `${COMMITMENT_DOMAIN}${trustRootJson}`,
    "utf8"
  ));
  const committed = validateTrustRoot(
    trustRootJson,
    trustRootCommitment,
    code
  );
  const secret = {
    schemaVersion: SECRET_SCHEMA,
    operationId: binding.operationId,
    sourceCommit: binding.sourceCommit,
    treeDigest: binding.treeDigest,
    publisherKeyId,
    privateKeyPkcs8Base64: privateKey.toString("base64"),
    trustRootJson,
    trustRootCommitment,
    publisherKeySetDigest: committed.publisherKeySetDigest
  };
  privateKey.fill(0);
  publicKey.fill(0);
  return validateFreshRecoveryPublisherSecret(secret, binding);
}

export function generateFreshRecoveryPublisherSecret(binding) {
  const code = "FRESH_RECOVERY_PUBLISHER_GENERATION_REJECTED";
  validateBinding(binding, code);
  let privateKey;
  let publicKey;
  try {
    ({ privateKey, publicKey } = generateKeyPairSync("ec", {
      namedCurve: "P-256",
      privateKeyEncoding: { format: "der", type: "pkcs8" },
      publicKeyEncoding: { format: "der", type: "spki" }
    }));
  } catch (cause) {
    reject(code, cause);
  }
  return publisherSecretFromDer(binding, privateKey, publicKey, code);
}

export function deriveFreshRecoveryPublisherSecret(binding, keyMaterial) {
  const code = "FRESH_RECOVERY_PUBLISHER_DERIVATION_REJECTED";
  validateBinding(binding, code);
  requireCondition((Buffer.isBuffer(keyMaterial) ||
      keyMaterial instanceof Uint8Array) && keyMaterial.byteLength >= 32 &&
    keyMaterial.byteLength <= 64 * 1024, code);
  const key = Buffer.from(keyMaterial);
  let scalar;
  let publicPoint;
  let privateDer;
  let publicDer;
  try {
    for (let counter = 0; counter < 256; counter += 1) {
      const counterBytes = Buffer.alloc(4);
      counterBytes.writeUInt32BE(counter);
      const candidate = createHmac("sha256", key)
        .update(DERIVATION_DOMAIN, "utf8")
        .update(canonicalBytes(binding))
        .update(counterBytes)
        .digest();
      const integer = BigInt(`0x${candidate.toString("hex")}`);
      if (integer > 0n && integer < P256_ORDER) {
        scalar = candidate;
        break;
      }
      candidate.fill(0);
    }
    requireCondition(Buffer.isBuffer(scalar), code);
    const ecdh = createECDH("prime256v1");
    ecdh.setPrivateKey(scalar);
    publicPoint = ecdh.getPublicKey(undefined, "uncompressed");
    requireCondition(publicPoint.length === 65 && publicPoint[0] === 4, code);
    const privateKey = createPrivateKey({
      format: "jwk",
      key: {
        crv: "P-256",
        d: scalar.toString("base64url"),
        kty: "EC",
        x: publicPoint.subarray(1, 33).toString("base64url"),
        y: publicPoint.subarray(33, 65).toString("base64url")
      }
    });
    privateDer = privateKey.export({ format: "der", type: "pkcs8" });
    publicDer = createPublicKey(privateKey).export({
      format: "der",
      type: "spki"
    });
    return publisherSecretFromDer(binding, privateDer, publicDer, code);
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    key.fill(0);
    scalar?.fill(0);
    publicPoint?.fill(0);
    privateDer?.fill(0);
    publicDer?.fill(0);
  }
}

export function freshRecoveryPublisherSecretBytes(value, binding) {
  const candidate = { ...value };
  delete candidate.secretBytesSha256;
  delete candidate.trustRootJsonSha256;
  const accepted = validateFreshRecoveryPublisherSecret(candidate, binding);
  const secret = { ...accepted };
  delete secret.secretBytesSha256;
  delete secret.trustRootJsonSha256;
  return canonicalBytes(secret);
}

export const __test = Object.freeze({
  canonicalBytes,
  canonicalJson,
  sha256,
  trustRootJsonFor
});
