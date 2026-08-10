import { createHash } from "node:crypto";

import { canonicalJson } from "./canonical-json.js";

function sha256(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}

function requireText(value, name) {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  return value;
}

export function trustedPublisherKeysDigest(trustedPublisherKeys) {
  if (
    !trustedPublisherKeys ||
    typeof trustedPublisherKeys !== "object" ||
    Array.isArray(trustedPublisherKeys)
  ) {
    throw new TypeError("trustedPublisherKeys must be an object");
  }
  const normalized = Object.entries(trustedPublisherKeys)
    .map(([keyId, publicKeySpkiBase64]) => {
      const encoded = requireText(
        publicKeySpkiBase64,
        `trustedPublisherKeys.${keyId}`
      );
      const bytes = Buffer.from(encoded, "base64");
      if (
        bytes.length === 0 ||
        bytes.toString("base64").replace(/=+$/u, "") !==
          encoded.replace(/=+$/u, "")
      ) {
        throw new TypeError(
          `trustedPublisherKeys.${keyId} must be canonical base64`
        );
      }
      return {
        keyId: requireText(keyId, "trustedPublisherKeys keyId"),
        publicKeyDigest: createHash("sha256").update(bytes).digest("hex")
      };
    })
    .sort(({ keyId: left }, { keyId: right }) => left.localeCompare(right));
  if (normalized.length === 0) {
    throw new TypeError("trustedPublisherKeys must not be empty");
  }
  return sha256(canonicalJson(normalized));
}
