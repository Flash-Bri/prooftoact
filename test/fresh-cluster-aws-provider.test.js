import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import {
  __test,
  normalizeFreshClusterAdminSealReadback
} from "../scripts/fresh-cluster-aws-provider.js";

const OPERATION_ID = "123e4567-e89b-42d3-a456-426614174000";
const ARN = "arn:aws:secretsmanager:us-east-1:111111111111:secret:" +
  `prooftoact/fresh-primary/admin-${OPERATION_ID}-Ab12Cd`;
const VERSION = "1".repeat(32);
const VALUE = "postgresql://prooftoact_bootstrap_admin:" +
  "provider-password:@fresh.aws.cockroachlabs.cloud:26257/" +
  "defaultdb?sslmode=verify-full";

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function description(stages = {}) {
  return {
    ARN,
    Name: `prooftoact/fresh-primary/admin-${OPERATION_ID}`,
    RotationEnabled: false,
    Tags: [
      { Key: "Project", Value: "ProofToAct" },
      { Key: "Purpose", Value: "FreshBootstrapAdmin" },
      { Key: "OperationId", Value: OPERATION_ID }
    ],
    VersionIdsToStages: stages
  };
}

test("admin prestate is empty and post-seal metadata binds one exact version", () => {
  const coordinate = { arn: ARN, versionId: VERSION };
  const prestate = __test.validateAdminSecretPrestate(
    description(),
    { ARN },
    null,
    coordinate,
    OPERATION_ID
  );
  assert.equal(prestate.targetVersionAbsent, true);
  const receipt = normalizeFreshClusterAdminSealReadback({
    command: { operationId: OPERATION_ID },
    coordinate,
    description: description({ [VERSION]: ["AWSCURRENT"] }),
    readback: {
      ARN,
      CreatedDate: new Date("2026-08-19T08:00:00.000Z"),
      SecretString: VALUE,
      VersionId: VERSION,
      VersionStages: ["AWSCURRENT"]
    },
    resourcePolicy: { ARN },
    secretValueSha256: sha256(VALUE)
  });
  assert.equal(receipt.status, "SEALED");
  assert.equal(receipt.immutableVersion, true);
  assert.throws(() => normalizeFreshClusterAdminSealReadback({
    command: { operationId: OPERATION_ID },
    coordinate,
    description: description({
      [VERSION]: ["AWSCURRENT"],
      ["2".repeat(32)]: ["AWSPREVIOUS"]
    }),
    readback: {
      ARN,
      CreatedDate: new Date("2026-08-19T08:00:00.000Z"),
      SecretString: VALUE,
      VersionId: VERSION,
      VersionStages: ["AWSCURRENT"]
    },
    resourcePolicy: { ARN },
    secretValueSha256: sha256(VALUE)
  }), /FRESH_CLUSTER_AWS_ADMIN_SECRET_SEAL_READBACK_REJECTED/u);
});
