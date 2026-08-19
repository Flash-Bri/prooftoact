import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import {
  PROOFTOACT_IMESSAGE_MATERIALIZER,
  buildProofToActImessageEventReceiptSha256,
  buildProofToActImessageMaterializer,
  buildProofToActB0A1HumanAuthorizationReceiptBinding,
  buildProofToActHumanAuthorizationSignaturePayload,
  renderProofToActB0A1ApprovalReply,
  renderProofToActB0A1HumanAuthorization,
  validateProofToActB0A1DynamicAuthorizationBinding,
  validateProofToActB0A1HumanAuthorizationReceipt
} from "./lib/prooftoact-b0-a1-human-authorization.js";

const execFileAsync = promisify(execFile);
const CURRENT_FILE = fileURLToPath(import.meta.url);
const IMSG_PATH = PROOFTOACT_IMESSAGE_MATERIALIZER.executablePath;
const IMSG_REALPATH = PROOFTOACT_IMESSAGE_MATERIALIZER.executableRealpath;
const IMSG_SHA256 = PROOFTOACT_IMESSAGE_MATERIALIZER.executableSha256;
const IMSG_VERSION = PROOFTOACT_IMESSAGE_MATERIALIZER.version;
const HISTORY_CHAT_ID = PROOFTOACT_IMESSAGE_MATERIALIZER.historyChatId;
const HISTORY_LIMIT = 10000;
const CHATS_ARGUMENTS = Object.freeze([
  "chats", "--limit", String(PROOFTOACT_IMESSAGE_MATERIALIZER.chatsLimit),
  "--json"
]);
const MAXIMUM_CHATS_BYTES = 1024 * 1024;
const MAXIMUM_HISTORY_BYTES = 64 * 1024 * 1024;
const MAXIMUM_MESSAGE_TEXT_BYTES = 256 * 1024;
const IDENTITY_HMAC_KEY_BYTES = 32;
const CONVERSATION_HMAC_DOMAIN =
  "ProofToAct/private-imessage-conversation/v1\0";
const SENDER_HMAC_DOMAIN = "ProofToAct/private-imessage-sender/v1\0";
const IDENTITY_RECORD_HMAC_DOMAIN =
  "ProofToAct/private-imessage-identity-record/v1\0";
const AUTHORIZATION_SIGNING_SEED_DOMAIN =
  "ProofToAct/private-imessage-authorization-signing-seed/v1\0";
const ED25519_PKCS8_SEED_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex"
);

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function plainObject(value) {
  return value !== null && typeof value === "object" &&
    !Array.isArray(value) && [Object.prototype, null].includes(
      Object.getPrototypeOf(value)
    );
}

function exactKeys(value, expected) {
  return plainObject(value) && Object.keys(value).sort().join("\n") ===
    [...expected].sort().join("\n");
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (plainObject(value)) {
    return Object.fromEntries(Object.keys(value).sort().map((key) =>
      [key, canonicalValue(value[key])]));
  }
  requireCondition(value === null || typeof value === "string" ||
    typeof value === "boolean" ||
    typeof value === "number" && Number.isSafeInteger(value),
  "PROOFTOACT_IMESSAGE_AUTHORIZATION_CANONICAL_REJECTED");
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

function canonicalBytes(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, "utf8");
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function digest(value) {
  return sha256(canonicalBytes(value));
}

function validateHmacKey(value, code) {
  requireCondition(Buffer.isBuffer(value) &&
    value.length === IDENTITY_HMAC_KEY_BYTES &&
    !value.equals(Buffer.alloc(IDENTITY_HMAC_KEY_BYTES)) &&
    new Set(value).size >= 16, code);
  return value;
}

function validatePrivateIdentityRecord(value, code) {
  requireCondition(exactKeys(value, [
    "expectedConversation", "schemaVersion"
  ]) && value.schemaVersion ===
    "prooftoact.private-imessage-authority-identity-record.v1" &&
    exactKeys(value.expectedConversation, [
      "chatGuid", "chatId", "chatIdentifier", "isGroup", "participant"
    ]) && value.expectedConversation.chatId === HISTORY_CHAT_ID &&
    value.expectedConversation.isGroup === false &&
    [value.expectedConversation.chatGuid,
      value.expectedConversation.chatIdentifier,
      value.expectedConversation.participant].every((item) =>
      typeof item === "string" && item.length > 0 && item.length <= 1024),
  code);
  return value;
}

export function parseProofToActPrivateImessageIdentityRecord(bytes) {
  const code = "PROOFTOACT_IMESSAGE_AUTHORIZATION_IDENTITY_RECORD_REJECTED";
  requireCondition(Buffer.isBuffer(bytes) && bytes.length > 0 &&
    bytes.length <= 16 * 1024 && bytes.at(-1) === 0x0a, code);
  let record;
  try {
    record = JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    reject(code, cause);
  }
  validatePrivateIdentityRecord(record, code);
  requireCondition(canonicalBytes(record).equals(bytes), code);
  return Object.freeze({
    record: Object.freeze({
      expectedConversation: Object.freeze({ ...record.expectedConversation }),
      schemaVersion: record.schemaVersion
    })
  });
}

function hmacSha256(key, domain, bytes) {
  validateHmacKey(key,
    "PROOFTOACT_IMESSAGE_AUTHORIZATION_HMAC_KEY_REJECTED");
  requireCondition(Buffer.isBuffer(bytes) && bytes.length > 0,
    "PROOFTOACT_IMESSAGE_AUTHORIZATION_HMAC_VALUE_REJECTED");
  return crypto.createHmac("sha256", key)
    .update(domain, "utf8")
    .update(bytes)
    .digest("hex");
}

function authorizationSigner(hmacKey) {
  validateHmacKey(hmacKey,
    "PROOFTOACT_IMESSAGE_AUTHORIZATION_SIGNER_REJECTED");
  const seed = crypto.createHmac("sha256", hmacKey)
    .update(AUTHORIZATION_SIGNING_SEED_DOMAIN, "utf8")
    .digest();
  try {
    const privateKey = crypto.createPrivateKey({
      format: "der",
      key: Buffer.concat([ED25519_PKCS8_SEED_PREFIX, seed]),
      type: "pkcs8"
    });
    const publicKeySpki = crypto.createPublicKey(privateKey).export({
      format: "der",
      type: "spki"
    });
    requireCondition(Buffer.isBuffer(publicKeySpki) &&
      publicKeySpki.length === 44,
    "PROOFTOACT_IMESSAGE_AUTHORIZATION_SIGNER_REJECTED");
    return Object.freeze({
      privateKey,
      publicKeySha256: sha256(publicKeySpki),
      publicKeySpkiBase64: publicKeySpki.toString("base64")
    });
  } catch (cause) {
    if (cause?.message ===
      "PROOFTOACT_IMESSAGE_AUTHORIZATION_SIGNER_REJECTED") throw cause;
    reject("PROOFTOACT_IMESSAGE_AUTHORIZATION_SIGNER_REJECTED", cause);
  } finally {
    seed.fill(0);
  }
}

function canonicalInstant(value, code) {
  const milliseconds = Date.parse(value);
  requireCondition(typeof value === "string" && Number.isFinite(milliseconds) &&
    new Date(milliseconds).toISOString() === value, code);
  return milliseconds;
}

function materializerReceipt() {
  return PROOFTOACT_IMESSAGE_MATERIALIZER;
}

function exactCommandEnvironment() {
  const code = "PROOFTOACT_IMESSAGE_AUTHORIZATION_ENVIRONMENT_REJECTED";
  requireCondition(typeof process.env.HOME === "string" &&
    path.isAbsolute(process.env.HOME), code);
  return Object.freeze({
    HOME: process.env.HOME,
    LANG: "C",
    LC_ALL: "C",
    PATH: "/usr/bin:/bin"
  });
}

async function executePinnedImsg(argumentsValue, maximumBytes) {
  const code = "PROOFTOACT_IMESSAGE_AUTHORIZATION_TOOL_REJECTED";
  try {
    const link = fs.lstatSync(IMSG_PATH);
    const realpath = fs.realpathSync(IMSG_PATH);
    const executable = fs.lstatSync(realpath);
    requireCondition(link.isSymbolicLink() && realpath === IMSG_REALPATH &&
      executable.isFile() && !executable.isSymbolicLink() &&
      (executable.mode & 0o022) === 0 &&
      sha256(fs.readFileSync(realpath)) === IMSG_SHA256, code);
    const environment = exactCommandEnvironment();
    const versionResult = await execFileAsync(IMSG_PATH, ["--version"], {
      cwd: "/",
      encoding: "utf8",
      env: environment,
      maxBuffer: 4 * 1024,
      timeout: 5_000,
      windowsHide: true
    });
    requireCondition(versionResult.stdout === `${IMSG_VERSION}\n` &&
      versionResult.stderr === "", code);
    const result = await execFileAsync(IMSG_PATH, argumentsValue, {
      cwd: "/",
      encoding: "utf8",
      env: environment,
      maxBuffer: maximumBytes,
      timeout: 30_000,
      windowsHide: true
    });
    requireCondition(result.stderr === "" &&
      Buffer.byteLength(result.stdout, "utf8") <= maximumBytes, code);
    return result.stdout;
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  }
}

export async function executePinnedImsgChats() {
  return Object.freeze({
    chatsStdout: await executePinnedImsg(
      CHATS_ARGUMENTS,
      MAXIMUM_CHATS_BYTES
    ),
    materializer: materializerReceipt()
  });
}

export async function executePinnedImsgHistory(dynamicIntent) {
  const intent = validateProofToActB0A1DynamicAuthorizationBinding(
    dynamicIntent
  );
  const materializer = buildProofToActImessageMaterializer(intent);
  const historyArguments = Object.freeze([
    "history", "--chat-id", String(HISTORY_CHAT_ID), "--start",
    materializer.history.start, "--end", materializer.history.end,
    "--limit", String(materializer.history.limit), "--json"
  ]);
  const [chatsStdout, historyStdout] = await Promise.all([
    executePinnedImsg(CHATS_ARGUMENTS, MAXIMUM_CHATS_BYTES),
    executePinnedImsg(historyArguments, MAXIMUM_HISTORY_BYTES)
  ]);
  return Object.freeze({ chatsStdout, historyStdout, materializer });
}

function parseJsonLines(stdout, maximumBytes, maximumRecords, code) {
  requireCondition(typeof stdout === "string" && stdout.endsWith("\n") &&
    !stdout.includes("\0") && Buffer.byteLength(stdout, "utf8") > 0 &&
    Buffer.byteLength(stdout, "utf8") <= maximumBytes, code);
  const lines = stdout.slice(0, -1).split("\n");
  requireCondition(lines.length > 0 && lines.length <= maximumRecords &&
    lines.every((line) => line.length > 0), code);
  return Object.freeze(lines.map((line) => {
    let record;
    try {
      record = JSON.parse(line);
    } catch (cause) {
      reject(code, cause);
    }
    requireCondition(plainObject(record), code);
    return record;
  }));
}

export function deriveProofToActImessageAuthorityIdentity({
  chatsStdout,
  hmacKey,
  identityRecordBytes,
  materializer
}) {
  const code = "PROOFTOACT_IMESSAGE_AUTHORIZATION_IDENTITY_REJECTED";
  requireCondition(canonicalJson(materializer) ===
    canonicalJson(materializerReceipt()), code);
  validateHmacKey(hmacKey, code);
  const parsedRecord = parseProofToActPrivateImessageIdentityRecord(
    identityRecordBytes
  );
  const records = parseJsonLines(chatsStdout, MAXIMUM_CHATS_BYTES,
    materializer.chatsLimit, code);
  const candidates = records.filter((record) =>
    record.id === HISTORY_CHAT_ID && record.is_group === false &&
    typeof record.guid === "string" && record.guid.length > 0 &&
    record.guid.length <= 1024 && typeof record.identifier === "string" &&
    record.identifier.length > 0 && record.identifier.length <= 1024 &&
    Array.isArray(record.participants) && record.participants.length === 1 &&
    typeof record.participants[0] === "string" &&
    record.participants[0].length > 0 && record.participants[0].length <= 1024
  );
  requireCondition(candidates.length === 1, code);
  const selected = candidates[0];
  const conversation = {
    chatGuid: selected.guid,
    chatId: selected.id,
    chatIdentifier: selected.identifier,
    isGroup: selected.is_group,
    participant: selected.participants[0]
  };
  requireCondition(canonicalJson(conversation) === canonicalJson(
    parsedRecord.record.expectedConversation
  ), code);
  const body = {
    schemaVersion: "prooftoact.private-imessage-authority-identity.v2",
    conversationHmacSha256: hmacSha256(
      hmacKey,
      CONVERSATION_HMAC_DOMAIN,
      canonicalBytes(conversation)
    ),
    hmacKeySha256: sha256(hmacKey),
    identityRecordHmacSha256: hmacSha256(
      hmacKey,
      IDENTITY_RECORD_HMAC_DOMAIN,
      identityRecordBytes
    ),
    materializer,
    signerPublicKeySha256: authorizationSigner(hmacKey).publicKeySha256,
    senderHmacSha256: hmacSha256(
      hmacKey,
      SENDER_HMAC_DOMAIN,
      Buffer.from(selected.participants[0], "utf8")
    )
  };
  return Object.freeze({ ...body, identityReceiptSha256: digest(body) });
}

export function buildProofToActPrivateImessageIdentityRecord({
  chatsStdout,
  materializer
}) {
  const code = "PROOFTOACT_IMESSAGE_AUTHORIZATION_IDENTITY_PACKET_REJECTED";
  requireCondition(canonicalJson(materializer) ===
    canonicalJson(materializerReceipt()), code);
  const records = parseJsonLines(chatsStdout, MAXIMUM_CHATS_BYTES,
    materializer.chatsLimit, code);
  const candidates = records.filter((record) =>
    record.id === HISTORY_CHAT_ID && record.is_group === false &&
    typeof record.guid === "string" && record.guid.length > 0 &&
    record.guid.length <= 1024 && typeof record.identifier === "string" &&
    record.identifier.length > 0 && record.identifier.length <= 1024 &&
    Array.isArray(record.participants) && record.participants.length === 1 &&
    typeof record.participants[0] === "string" &&
    record.participants[0].length > 0 && record.participants[0].length <= 1024
  );
  requireCondition(candidates.length === 1, code);
  const selected = candidates[0];
  const record = {
    expectedConversation: {
      chatGuid: selected.guid,
      chatId: selected.id,
      chatIdentifier: selected.identifier,
      isGroup: selected.is_group,
      participant: selected.participants[0]
    },
    schemaVersion:
      "prooftoact.private-imessage-authority-identity-record.v1"
  };
  validatePrivateIdentityRecord(record, code);
  return Object.freeze(record);
}

export function parsePinnedImsgHistory(stdout) {
  const code = "PROOFTOACT_IMESSAGE_AUTHORIZATION_HISTORY_REJECTED";
  const records = parseJsonLines(stdout, MAXIMUM_HISTORY_BYTES,
    HISTORY_LIMIT, code);
  return Object.freeze(records.map((record) => {
    requireCondition(record.chat_id === HISTORY_CHAT_ID &&
      typeof record.chat_guid === "string" && record.chat_guid.length > 0 &&
      record.chat_guid.length <= 1024 &&
      typeof record.chat_identifier === "string" &&
      record.chat_identifier.length > 0 &&
      record.chat_identifier.length <= 1024 &&
      record.is_group === false && Array.isArray(record.participants) &&
      record.participants.length === 1 &&
      typeof record.participants[0] === "string" &&
      record.participants[0].length > 0 &&
      record.participants[0].length <= 1024 &&
      typeof record.guid === "string" && record.guid.length > 0 &&
      record.guid.length <= 1024 &&
      (record.text === null || typeof record.text === "string" &&
        Buffer.byteLength(record.text, "utf8") <=
          MAXIMUM_MESSAGE_TEXT_BYTES) &&
      typeof record.is_from_me === "boolean" &&
      Array.isArray(record.attachments),
    code);
    canonicalInstant(record.created_at, code);
    return Object.freeze(record);
  }));
}

export function materializeProofToActB0A1HumanAuthorizationEvidence({
  chatsStdout,
  dynamicIntent,
  historyStdout,
  hmacKey,
  identityRecordBytes,
  materializer,
}) {
  const code = "PROOFTOACT_IMESSAGE_AUTHORIZATION_EVENTS_REJECTED";
  const intent = validateProofToActB0A1DynamicAuthorizationBinding(
    dynamicIntent
  );
  requireCondition(canonicalJson(materializer) === canonicalJson(
    buildProofToActImessageMaterializer(intent)
  ), code);
  validateHmacKey(hmacKey, code);
  const parsedRecord = parseProofToActPrivateImessageIdentityRecord(
    identityRecordBytes
  );
  requireCondition(sha256(hmacKey) === intent.humanIdentityHmacKeySha256,
    code);
  const identity = deriveProofToActImessageAuthorityIdentity({
    chatsStdout,
    hmacKey,
    identityRecordBytes,
    materializer: materializer.tool
  });
  requireCondition(identity.conversationHmacSha256 ===
    intent.humanAuthorizationConversationHmacSha256 &&
    identity.signerPublicKeySha256 ===
      intent.humanAuthorizationSignerPublicKeySha256 &&
    identity.senderHmacSha256 === intent.humanAuthoritySenderHmacSha256 &&
    identity.hmacKeySha256 === intent.humanIdentityHmacKeySha256 &&
    identity.identityRecordHmacSha256 ===
      intent.humanIdentityRecordHmacSha256 &&
    identity.identityReceiptSha256 === intent.humanIdentityReceiptSha256,
  code);
    const rendered = renderProofToActB0A1HumanAuthorization(intent);
    const approvalReply = renderProofToActB0A1ApprovalReply(intent);
    const records = parsePinnedImsgHistory(historyStdout);
    const notBefore = Date.parse(intent.authorizationNotBefore);
    const deadline = Date.parse(intent.b0DispatchDeadline);
    const outboundCandidates = records.filter((record) =>
    record.is_from_me === true && record.text === rendered.text &&
    record.attachments.length === 0 &&
    Date.parse(record.created_at) >= notBefore &&
    Date.parse(record.created_at) < deadline &&
    hmacSha256(hmacKey, CONVERSATION_HMAC_DOMAIN, canonicalBytes({
      chatGuid: record.chat_guid,
      chatId: record.chat_id,
      chatIdentifier: record.chat_identifier,
      isGroup: record.is_group,
      participant: record.participants[0]
    })) === identity.conversationHmacSha256
    );
    requireCondition(outboundCandidates.length === 1, code);
    const outbound = outboundCandidates[0];
    const inboundCandidates = records.filter((record) =>
    record.is_from_me === false && record.text === approvalReply.text &&
    record.attachments.length === 0 &&
    typeof record.sender === "string" && record.sender.length > 0 &&
    record.sender.length <= 1024 &&
    typeof record.reply_to_guid === "string" &&
    record.reply_to_guid === outbound.guid &&
    record.chat_guid === outbound.chat_guid &&
    Date.parse(record.created_at) >= Date.parse(outbound.created_at) &&
    Date.parse(record.created_at) < deadline &&
    hmacSha256(hmacKey, SENDER_HMAC_DOMAIN,
      Buffer.from(record.sender, "utf8")) === identity.senderHmacSha256 &&
    hmacSha256(hmacKey, CONVERSATION_HMAC_DOMAIN, canonicalBytes({
      chatGuid: record.chat_guid,
      chatId: record.chat_id,
      chatIdentifier: record.chat_identifier,
      isGroup: record.is_group,
      participant: record.participants[0]
    })) === identity.conversationHmacSha256
    );
    requireCondition(inboundCandidates.length === 1, code);
    const inbound = inboundCandidates[0];
    const outboundEvent = {
    bodySha256: rendered.sha256,
    bodyText: rendered.text,
    channel: "imessage",
    conversationHmacSha256: identity.conversationHmacSha256,
    messageIdSha256: sha256(Buffer.from(outbound.guid, "utf8")),
    provider: "imessage",
    sentAt: outbound.created_at
    };
    outboundEvent.eventReceiptSha256 =
    buildProofToActImessageEventReceiptSha256({
      direction: "OUTBOUND",
      event: outboundEvent,
      materializer
    });
    const inboundEvent = {
    bodySha256: approvalReply.sha256,
    bodyText: approvalReply.text,
    channel: "imessage",
    conversationHmacSha256: identity.conversationHmacSha256,
    messageIdSha256: sha256(Buffer.from(inbound.guid, "utf8")),
    provider: "imessage",
    receivedAt: inbound.created_at,
    replyTargetMessageIdSha256:
      sha256(Buffer.from(inbound.reply_to_guid, "utf8")),
    senderHmacSha256: identity.senderHmacSha256
    };
    inboundEvent.eventReceiptSha256 =
    buildProofToActImessageEventReceiptSha256({
      direction: "INBOUND",
      event: inboundEvent,
      materializer
    });
    const unsignedEvidence = Object.freeze({
      authorityId: "REVIEWED_DIRECT_HUMAN_OPERATOR",
      inboundApprovalEvent: Object.freeze(inboundEvent),
      materializer,
      outboundAuthorizationEvent: Object.freeze(outboundEvent),
      schemaVersion: "prooftoact.external-human-authorization-evidence.v4"
    });
    const signer = authorizationSigner(hmacKey);
    requireCondition(signer.publicKeySha256 ===
      intent.humanAuthorizationSignerPublicKeySha256, code);
    const signaturePayload =
      buildProofToActHumanAuthorizationSignaturePayload({
        dynamicIntentSha256: intent.dynamicIntentSha256,
        unsignedExternalHumanAuthorizationEvidenceSha256:
          digest(unsignedEvidence)
      });
    const signature = crypto.sign(null, signaturePayload.bytes,
      signer.privateKey);
    requireCondition(signature.length === 64, code);
    return Object.freeze({
      ...unsignedEvidence,
      authorizationSignatureBase64: signature.toString("base64"),
      signerPublicKeySpkiBase64: signer.publicKeySpkiBase64
    });
}

export async function collectProofToActB0A1HumanAuthorizationEvidence(
  dynamicIntent,
  identityRecordBytes,
  hmacKey,
  { executeHistory = executePinnedImsgHistory } = {}
) {
  const observed = await executeHistory(dynamicIntent);
  return materializeProofToActB0A1HumanAuthorizationEvidence({
    chatsStdout: observed.chatsStdout,
    dynamicIntent,
    historyStdout: observed.historyStdout,
    hmacKey,
    identityRecordBytes,
    materializer: observed.materializer,
  });
}

export async function verifyProofToActB0A1HumanAuthorizationWithImsg(
  receipt,
  identityRecordBytes,
  hmacKey,
  { executeHistory = executePinnedImsgHistory } = {}
) {
  const code = "PROOFTOACT_IMESSAGE_AUTHORIZATION_LIVE_READBACK_REJECTED";
  const validated = validateProofToActB0A1HumanAuthorizationReceipt(receipt);
  const observed = await collectProofToActB0A1HumanAuthorizationEvidence(
    validated.dynamicIntent,
    identityRecordBytes,
    hmacKey,
    { executeHistory }
  );
  requireCondition(canonicalJson(observed) === canonicalJson(
    validated.externalHumanAuthorizationEvidence
  ), code);
  return validated;
}

function readOwnerOnlyBytes(filePath, maximumBytes, code) {
  requireCondition(path.isAbsolute(filePath), code);
  let descriptor;
  try {
    descriptor = fs.openSync(filePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const before = fs.fstatSync(descriptor);
    requireCondition(before.isFile() && !before.isSymbolicLink() &&
      before.uid === process.getuid() && before.nlink === 1 &&
      (before.mode & 0o077) === 0 && before.size > 0 &&
      before.size <= maximumBytes, code);
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    requireCondition(before.dev === after.dev && before.ino === after.ino &&
      before.mode === after.mode && before.size === after.size &&
      bytes.length === before.size, code);
    return bytes;
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

function readOwnerOnlyJson(filePath, maximumBytes, code) {
  const bytes = readOwnerOnlyBytes(filePath, maximumBytes, code);
  try {
    return JSON.parse(bytes.toString("utf8"));
  } catch (cause) {
    reject(code, cause);
  } finally {
    bytes.fill(0);
  }
}

function writeOwnerOnlyExclusiveBytes(filePath, bytes) {
  const code = "PROOFTOACT_IMESSAGE_AUTHORIZATION_OUTPUT_REJECTED";
  requireCondition(path.isAbsolute(filePath) && Buffer.isBuffer(bytes) &&
    bytes.length > 0 && bytes.length <= 256 * 1024, code);
  const parent = fs.realpathSync(path.dirname(filePath));
  const stat = fs.statSync(parent);
  requireCondition(parent === path.dirname(filePath) && stat.isDirectory() &&
    stat.uid === process.getuid() && (stat.mode & 0o077) === 0, code);
  let descriptor;
  try {
    descriptor = fs.openSync(filePath,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY |
      fs.constants.O_NOFOLLOW, 0o600);
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
    const written = fs.fstatSync(descriptor);
    requireCondition(written.isFile() && written.uid === process.getuid() &&
      written.nlink === 1 && (written.mode & 0o077) === 0 &&
      written.size === bytes.length, code);
  } catch (cause) {
    if (cause?.message === code) throw cause;
    reject(code, cause);
  } finally {
    if (Number.isSafeInteger(descriptor)) fs.closeSync(descriptor);
  }
}

function writeOwnerOnlyExclusive(filePath, value) {
  writeOwnerOnlyExclusiveBytes(filePath, canonicalBytes(value));
}

function parseArguments(argv) {
  const code = "PROOFTOACT_IMESSAGE_AUTHORIZATION_ARGUMENTS_REJECTED";
  requireCondition(Array.isArray(argv) && [4, 8, 12].includes(argv.length),
    code);
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    requireCondition([
      "--candidate-identity-record-file", "--dynamic-intent-file",
      "--expected-identity-record-file", "--hmac-key-file",
      "--identity-receipt-file", "--mode", "--output-file"
    ].includes(name) && !Object.hasOwn(values, name) &&
      typeof value === "string", code);
    values[name] = value;
  }
  const observe = values["--mode"] === "OBSERVE" &&
    Object.keys(values).sort().join("\n") === [
      "--candidate-identity-record-file", "--mode"
    ].sort().join("\n");
  const identity = values["--mode"] === "IDENTITY" &&
    Object.keys(values).sort().join("\n") === [
      "--expected-identity-record-file", "--hmac-key-file",
      "--identity-receipt-file", "--mode"
    ].sort().join("\n");
  const finalize = values["--mode"] === "FINALIZE" &&
    Object.keys(values).sort().join("\n") === [
      "--dynamic-intent-file", "--hmac-key-file", "--mode", "--output-file",
      "--expected-identity-record-file", "--identity-receipt-file"
    ].sort().join("\n");
  requireCondition(observe || identity || finalize, code);
  for (const [name, value] of Object.entries(values)) {
    if (name !== "--mode") requireCondition(path.isAbsolute(value), code);
  }
  return Object.freeze(values);
}

async function main(argv = process.argv.slice(2)) {
  const parsed = parseArguments(argv);
  if (parsed["--mode"] === "OBSERVE") {
    const observed = await executePinnedImsgChats();
    const candidate = buildProofToActPrivateImessageIdentityRecord({
      chatsStdout: observed.chatsStdout,
      materializer: observed.materializer
    });
    writeOwnerOnlyExclusive(
      parsed["--candidate-identity-record-file"],
      candidate
    );
    process.stdout.write(
      "PROOFTOACT_PRIVATE_IMESSAGE_IDENTITY_CANDIDATE_REQUIRES_REVIEW\n"
    );
    return;
  }
  if (parsed["--mode"] === "IDENTITY") {
    const observed = await executePinnedImsgChats();
    const identityRecordBytes = readOwnerOnlyBytes(
      parsed["--expected-identity-record-file"],
      16 * 1024,
      "PROOFTOACT_IMESSAGE_AUTHORIZATION_IDENTITY_RECORD_FILE_REJECTED"
    );
    const hmacKey = crypto.randomBytes(IDENTITY_HMAC_KEY_BYTES);
    try {
      validateHmacKey(hmacKey,
        "PROOFTOACT_IMESSAGE_AUTHORIZATION_HMAC_KEY_FILE_REJECTED");
      const identity = deriveProofToActImessageAuthorityIdentity({
        chatsStdout: observed.chatsStdout,
        hmacKey,
        identityRecordBytes,
        materializer: observed.materializer
      });
      writeOwnerOnlyExclusiveBytes(parsed["--hmac-key-file"], hmacKey);
      writeOwnerOnlyExclusive(parsed["--identity-receipt-file"], identity);
      process.stdout.write(
        "PROOFTOACT_PRIVATE_IMESSAGE_AUTHORITY_IDENTITY_MATERIALIZED\n" +
        `identity_receipt_sha256=${identity.identityReceiptSha256}\n`
      );
      return;
    } finally {
      hmacKey.fill(0);
      identityRecordBytes.fill(0);
    }
  }
  const dynamicIntent = validateProofToActB0A1DynamicAuthorizationBinding(
    readOwnerOnlyJson(parsed["--dynamic-intent-file"], 256 * 1024,
      "PROOFTOACT_IMESSAGE_AUTHORIZATION_INPUT_REJECTED")
  );
  const observed = await executePinnedImsgHistory(dynamicIntent);
  const identityRecordBytes = readOwnerOnlyBytes(
    parsed["--expected-identity-record-file"],
    16 * 1024,
    "PROOFTOACT_IMESSAGE_AUTHORIZATION_IDENTITY_RECORD_FILE_REJECTED"
  );
  const hmacKey = readOwnerOnlyBytes(parsed["--hmac-key-file"],
    IDENTITY_HMAC_KEY_BYTES,
    "PROOFTOACT_IMESSAGE_AUTHORIZATION_HMAC_KEY_FILE_REJECTED");
  try {
    validateHmacKey(hmacKey,
      "PROOFTOACT_IMESSAGE_AUTHORIZATION_HMAC_KEY_FILE_REJECTED");
    const identity = deriveProofToActImessageAuthorityIdentity({
      chatsStdout: observed.chatsStdout,
      hmacKey,
      identityRecordBytes,
      materializer: observed.materializer.tool
    });
    const priorIdentity = readOwnerOnlyJson(
      parsed["--identity-receipt-file"],
      64 * 1024,
      "PROOFTOACT_IMESSAGE_AUTHORIZATION_IDENTITY_FILE_REJECTED"
    );
    requireCondition(canonicalJson(priorIdentity) === canonicalJson(identity),
      "PROOFTOACT_IMESSAGE_AUTHORIZATION_IDENTITY_FILE_REJECTED");
    const externalHumanAuthorizationEvidence =
      materializeProofToActB0A1HumanAuthorizationEvidence({
        chatsStdout: observed.chatsStdout,
        dynamicIntent,
        historyStdout: observed.historyStdout,
        hmacKey,
        identityRecordBytes,
        materializer: observed.materializer
      });
    const receipt = buildProofToActB0A1HumanAuthorizationReceiptBinding({
      dynamicIntent,
      externalHumanAuthorizationEvidence
    });
    writeOwnerOnlyExclusive(parsed["--output-file"], receipt);
    process.stdout.write(
      "PROOFTOACT_B0_A1_HUMAN_AUTHORIZATION_MATERIALIZED\n" +
      `receipt_binding_sha256=${receipt.receiptBindingSha256}\n`
    );
  } finally {
    hmacKey.fill(0);
    identityRecordBytes.fill(0);
  }
}

const startedDirectly = process.argv[1] &&
  path.resolve(process.argv[1]) === CURRENT_FILE;

if (startedDirectly) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  CHATS_ARGUMENTS,
  CONVERSATION_HMAC_DOMAIN,
  HISTORY_CHAT_ID,
  HISTORY_LIMIT,
  IMSG_PATH,
  IMSG_REALPATH,
  IMSG_SHA256,
  IMSG_VERSION,
  SENDER_HMAC_DOMAIN,
  canonicalJson,
  digest,
  materializerReceipt,
  parseArguments,
  sha256
});
