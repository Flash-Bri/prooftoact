import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { publishOrReadExactOwnedFile } from
  "../src/cloud/atomic-create-only-file.js";
import {
  brokerCanonicalBytes,
  brokerPublicKeyFingerprint,
  brokerSha256,
  providerBrokerConstants,
  validateProviderBrokerApproval
} from "./release-provider-one-shot-broker.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PUBLIC_KEY_PATH = path.join(
  ROOT,
  "config/prooftoact-release-operator-public.pub"
);
const TRUSTED_PUBLIC_KEY_FINGERPRINT =
  "9c4e4c9bdade64461547c8e511d525d8fc2e53ae0fc44642e52cf01978a08889";
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

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

function exactKeys(value, keys) {
  return plainObject(value) &&
    JSON.stringify(Object.keys(value).sort()) ===
      JSON.stringify([...keys].sort());
}

function publicDer(key) {
  const publicKey = key?.type === "public" ? key : crypto.createPublicKey(key);
  return publicKey.export({ format: "der", type: "spki" });
}

function validatePrivateKey(privateKeyPem, trustedPublicKeyPem) {
  const code = "PROVIDER_APPROVAL_SIGNER_KEY_REJECTED";
  let privateKey;
  let derived;
  try {
    privateKey = crypto.createPrivateKey(privateKeyPem);
    derived = crypto.createPublicKey(privateKey);
    requireCondition(privateKey.type === "private" &&
      privateKey.asymmetricKeyType === "ec" &&
      privateKey.asymmetricKeyDetails?.namedCurve === "prime256v1" &&
      publicDer(derived).equals(publicDer(trustedPublicKeyPem)), code);
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  }
  return privateKey;
}

export function deriveProviderApprovalWindow(expiresAt) {
  const code = "PROVIDER_APPROVAL_SIGNER_INPUT_REJECTED";
  const issued = Date.now();
  const issuedAt = new Date(issued).toISOString();
  const expires = Date.parse(expiresAt);
  requireCondition(typeof expiresAt === "string" && Number.isFinite(expires) &&
    issued < expires && expires - issued <= 30 * 60 * 1000 &&
    new Date(expires).toISOString() === expiresAt, code);
  return Object.freeze({ expires, issued, issuedAt });
}

export function signProviderBrokerApproval(options) {
  const code = "PROVIDER_APPROVAL_SIGNER_INPUT_REJECTED";
  requireCondition(exactKeys(options, [
    "claims", "expiresAt", "privateKeyPem", "trustedPublicKeyPem"
  ]), code);
  const {
    claims,
    expiresAt,
    privateKeyPem,
    trustedPublicKeyPem
  } = options;
  const { expires, issued, issuedAt } =
    deriveProviderApprovalWindow(expiresAt);
  requireCondition(plainObject(claims) && UUID.test(claims.approvalId ?? "") &&
    Number.isFinite(issued) && Number.isFinite(expires), code);
  const fingerprint = brokerPublicKeyFingerprint(trustedPublicKeyPem);
  const privateKey = validatePrivateKey(privateKeyPem, trustedPublicKeyPem);
  const unsigned = {
    schemaVersion: providerBrokerConstants.APPROVAL_SCHEMA,
    issuer: providerBrokerConstants.OPERATOR_ISSUER,
    keyFingerprint: fingerprint,
    nonce: claims.approvalId,
    issuedAt,
    expiresAt,
    claims
  };
  const signature = crypto.sign("sha256", brokerCanonicalBytes(unsigned), {
    dsaEncoding: "ieee-p1363",
    key: privateKey
  });
  requireCondition(signature.length === 64, code);
  const envelope = Object.freeze({
    ...unsigned,
    signature: signature.toString("base64")
  });
  validateProviderBrokerApproval(envelope, trustedPublicKeyPem, issued);
  return envelope;
}

function readExactOwnedFile(filePath, maximumBytes, code) {
  requireCondition(path.isAbsolute(filePath), code);
  const real = fs.realpathSync(filePath);
  const stat = fs.lstatSync(real);
  requireCondition(real === path.resolve(filePath) && stat.isFile() &&
    !stat.isSymbolicLink() && stat.nlink === 1 && stat.uid === process.getuid() &&
    (stat.mode & 0o022) === 0 && stat.size > 0 && stat.size <= maximumBytes,
  code);
  const bytes = fs.readFileSync(real);
  requireCondition(bytes.length === stat.size, code);
  return bytes;
}

function readExactJson(filePath, maximumBytes, code) {
  const bytes = readExactOwnedFile(filePath, maximumBytes, code);
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(brokerCanonicalBytes(value).equals(bytes), code);
  return value;
}

function assertPrivateRoot(rootPath, code) {
  requireCondition(path.isAbsolute(rootPath), code);
  const real = fs.realpathSync(rootPath);
  const stat = fs.lstatSync(real);
  requireCondition(real === path.resolve(rootPath) && stat.isDirectory() &&
    !stat.isSymbolicLink() && stat.uid === process.getuid() &&
    (stat.mode & 0o077) === 0, code);
  return real;
}

function readPrivateKeyFd(fd) {
  const code = "PROVIDER_APPROVAL_SIGNER_PRIVATE_FD_REJECTED";
  requireCondition(Number.isSafeInteger(fd) && fd >= 3, code);
  let bytes;
  try {
    bytes = fs.readFileSync(fd);
  } catch (cause) {
    reject(code, cause);
  }
  requireCondition(bytes.length > 0 && bytes.length <= 16 * 1024, code);
  return bytes;
}

function parseArguments(args) {
  const code = "PROVIDER_APPROVAL_SIGNER_ARGUMENTS_REJECTED";
  const allowed = new Set([
    "--claims", "--expires-at", "--key-fd", "--output-root"
  ]);
  requireCondition(args.length === allowed.size * 2, code);
  const parsed = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    requireCondition(allowed.has(name) && !Object.hasOwn(parsed, name) &&
      typeof value === "string" && value.length > 0, code);
    parsed[name] = value;
  }
  return parsed;
}

function rejectEnvironment(environment) {
  const forbidden = Object.keys(environment).filter((name) =>
    /^(?:ALL|HTTP|HTTPS|NO)_PROXY$/u.test(name) ||
    /^(?:DYLD_.+|LD_PRELOAD|NODE_COMPILE_CACHE|NODE_OPTIONS|NODE_PATH)$/u
      .test(name) ||
    /^AWS_(?:ACCESS_KEY_ID|CONFIG_FILE|PROFILE|SECRET_ACCESS_KEY|SESSION_TOKEN|SHARED_CREDENTIALS_FILE|WEB_IDENTITY_TOKEN_FILE)$/u.test(name) ||
    /OPENAI|OPENCLAW.*OAUTH|PRIVATE.*KEY|(?:npm_config_)?(?:https?_proxy|no_proxy)/iu
      .test(name)
  );
  requireCondition(forbidden.length === 0,
    "PROVIDER_APPROVAL_SIGNER_ENVIRONMENT_REJECTED");
}

export async function main(args = process.argv.slice(2), environment = process.env) {
  rejectEnvironment(environment);
  const parsed = parseArguments(args);
  const publicKeyBytes = readExactOwnedFile(
    PUBLIC_KEY_PATH,
    16 * 1024,
    "PROVIDER_APPROVAL_SIGNER_PUBLIC_KEY_REJECTED"
  );
  requireCondition(brokerPublicKeyFingerprint(publicKeyBytes) ===
    TRUSTED_PUBLIC_KEY_FINGERPRINT,
  "PROVIDER_APPROVAL_SIGNER_PUBLIC_KEY_REJECTED");
  const claims = readExactJson(
    path.resolve(parsed["--claims"]),
    512 * 1024,
    "PROVIDER_APPROVAL_SIGNER_CLAIMS_REJECTED"
  );
  const envelope = signProviderBrokerApproval({
    claims,
    expiresAt: parsed["--expires-at"],
    privateKeyPem: readPrivateKeyFd(Number(parsed["--key-fd"])),
    trustedPublicKeyPem: publicKeyBytes
  });
  const outputRoot = assertPrivateRoot(
    path.resolve(parsed["--output-root"]),
    "PROVIDER_APPROVAL_SIGNER_OUTPUT_REJECTED"
  );
  const filePath = path.join(outputRoot, `${claims.approvalId}.json`);
  const bytes = brokerCanonicalBytes(envelope);
  const publication = publishOrReadExactOwnedFile({
    assertRoot: () => assertPrivateRoot(
      outputRoot,
      "PROVIDER_APPROVAL_SIGNER_OUTPUT_REJECTED"
    ),
    bytes,
    code: "PROVIDER_APPROVAL_SIGNER_PUBLICATION_REJECTED",
    fault: () => {},
    filePath,
    maximumBytes: 1024 * 1024,
    mode: 0o600,
    rootPath: outputRoot
  });
  process.stdout.write(`${publication.created ? "CREATED" : "EXISTS"}:` +
    `${claims.approvalId}:${brokerSha256(bytes)}:${filePath}\n`);
}

const startedDirectly = process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (startedDirectly) {
  main().catch((error) => {
    const code = /^PROVIDER_APPROVAL_SIGNER_[A-Z0-9_]{1,100}$/u
      .test(String(error?.message ?? ""))
      ? error.message
      : "PROVIDER_APPROVAL_SIGNER_UNKNOWN_REJECTED";
    process.stderr.write(`HOLD:${code}\n`);
    process.exitCode = 1;
  });
}

export const approvalSignerConstants = Object.freeze({
  PUBLIC_KEY_PATH,
  TRUSTED_PUBLIC_KEY_FINGERPRINT
});
