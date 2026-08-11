import crypto from "node:crypto";

import { canonicalJson } from "./canonical-json.js";

const HEX_64 = /^[0-9a-f]{64}$/u;
const CONFIGURATION_KEYS = Object.freeze([
  "accountId",
  "apiAuthorization",
  "artifactBucket",
  "artifactCodeSha256",
  "artifactDigests",
  "artifactKeys",
  "artifactSourceDigests",
  "artifactVersions",
  "attestation",
  "authority",
  "bedrockModelId",
  "budgetUsd",
  "evidenceOperator",
  "logRetentionDays",
  "notificationEmailDigest",
  "packageLockDigest",
  "probesEnabled",
  "publicDemo",
  "region",
  "reservedConcurrency",
  "sourceCommit",
  "stackName",
  "templateDigest",
  "throttle",
  "treeDigest"
]);
const AUTHORITY_KEYS = Object.freeze([
  "databaseHost",
  "databasePort",
  "databaseSecretArn",
  "databaseSecretVersionId",
  "incidentId",
  "resourceId",
  "tenantId"
]);
const ATTESTATION_KEYS = Object.freeze([
  "alternateRolePolicyDigest",
  "evidenceRolePolicyDigest",
  "functionConfigurationDigests",
  "functionRolePolicyDigests",
  "receiptPublicKeys"
]);
const FUNCTION_NAMES = Object.freeze([
  "agent",
  "authority",
  "boundary",
  "demo",
  "signer"
]);

function exactKeys(value, keys) {
  return value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...keys].sort().join("\n");
}

function reject() {
  throw new Error("DEPLOYMENT_CONFIG_SHAPE_REJECTED");
}

export function deploymentConfigDigestPure(configuration) {
  if (
    !exactKeys(configuration, CONFIGURATION_KEYS) ||
    !exactKeys(configuration.authority, AUTHORITY_KEYS) ||
    !exactKeys(configuration.evidenceOperator, ["principalArn"]) ||
    !exactKeys(configuration.attestation, ATTESTATION_KEYS) ||
    !["functionConfigurationDigests", "functionRolePolicyDigests"].every(
      (name) =>
        exactKeys(configuration.attestation[name], FUNCTION_NAMES) &&
        Object.values(configuration.attestation[name]).every((value) =>
          HEX_64.test(value)
        )
    ) ||
    !HEX_64.test(
      configuration.attestation.evidenceRolePolicyDigest ?? ""
    ) ||
    !HEX_64.test(
      configuration.attestation.alternateRolePolicyDigest ?? ""
    ) ||
    !exactKeys(
      configuration.attestation.receiptPublicKeys,
      ["alternateDenial", "post", "pre"]
    ) ||
    !Object.values(configuration.attestation.receiptPublicKeys).every(
      (value) =>
        typeof value === "string" &&
        value.length >= 56 &&
        value.length <= 128 &&
        /^[A-Za-z0-9+/]+={0,2}$/u.test(value)
    )
  ) {
    reject();
  }
  const evidencePrincipalPattern = new RegExp(
    `^arn:aws[a-zA-Z-]*:iam::${configuration.accountId}:` +
      "(?:role|user)/[A-Za-z0-9+=,.@_-]{1,64}$",
    "u"
  );
  if (!evidencePrincipalPattern.test(
    configuration.evidenceOperator.principalArn
  )) {
    reject();
  }
  for (const publicKey of Object.values(
    configuration.attestation.receiptPublicKeys
  )) {
    try {
      const key = crypto.createPublicKey({
        key: Buffer.from(publicKey, "base64"),
        format: "der",
        type: "spki"
      });
      if (
        key.asymmetricKeyType !== "ed25519" ||
        key.export({ format: "der", type: "spki" }).toString("base64") !==
          publicKey
      ) {
        reject();
      }
    } catch {
      reject();
    }
  }
  if (
    new Set(Object.values(configuration.attestation.receiptPublicKeys)).size !==
      3
  ) {
    reject();
  }
  return crypto
    .createHash("sha256")
    .update(canonicalJson(configuration))
    .digest("hex");
}
