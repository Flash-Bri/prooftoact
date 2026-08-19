import assert from "node:assert/strict";
import test from "node:test";

import { __test } from "../scripts/fresh-cluster-aws-runtime.js";

const ACCOUNT = "111111111111";
const OPERATION_ID = "123e4567-e89b-42d3-a456-426614174000";
const ADMIN_VALUE =
  "postgresql://prooftoact_bootstrap_admin:private" +
  "@host:26257/defaultdb";
const coordinate = (name, version) => ({
  arn: `arn:aws:secretsmanager:us-east-1:${ACCOUNT}:secret:${name}`,
  versionId: version.repeat(32)
});
const COORDINATES = {
  admin: coordinate(
    `prooftoact/fresh-primary/admin-${OPERATION_ID}-Ab12Cd`, "1"
  ),
  auditor: coordinate(
    "prooftoact/fresh-cluster/auditor-Ef34Gh", "2"
  ),
  cloudApi: coordinate(
    "prooftoact/fresh-primary/cloud-api-Ij56Kl", "3"
  ),
  credential: coordinate(
    "prooftoact/fresh-primary/runtime-credentials-Mn78Op", "4"
  ),
  mcp: coordinate("prooftoact/gate2/managed-mcp-Uv34Wx", "6"),
  publisher: coordinate("prooftoact/gate2/recovery-publisher-Yz56Ab", "7"),
  signer: coordinate(
    `prooftoact/fresh-primary/recovery-signer-${OPERATION_ID}-Qr90St`, "5"
  )
};

test("fresh-cluster AWS coordinates are operation-bound and role-isolated", () => {
  assert.deepEqual(
    __test.validateSecretCoordinates(COORDINATES, ACCOUNT, OPERATION_ID),
    COORDINATES
  );
  assert.throws(() => __test.validateSecretCoordinates({
    ...COORDINATES,
    admin: coordinate(
      "prooftoact/fresh-primary/admin-223e4567-e89b-42d3-a456-426614174001-Ab12Cd",
      "1"
    )
  }, ACCOUNT, OPERATION_ID), /FRESH_CLUSTER_AWS_SECRET_COORDINATES_REJECTED/u);
  assert.throws(() => __test.validateSecretCoordinates({
    ...COORDINATES,
    auditor: COORDINATES.cloudApi
  }, ACCOUNT, OPERATION_ID), /FRESH_CLUSTER_AWS_SECRET_COORDINATES_REJECTED/u);
});

test("fresh-cluster DynamoDB guard accepts only its exact retained key family", () => {
  const accepted = {
    ConsistentRead: true,
    Key: { pk: { S: `FRESH_CLUSTER#${"a".repeat(64)}` } },
    ReturnConsumedCapacity: "NONE",
    TableName: "prooftoact-release-controller"
  };
  assert.doesNotThrow(() => __test.exactKey(accepted,
    "prooftoact-release-controller"));
  for (const pk of [
    `FRESH_PRIMARY#${"a".repeat(64)}`,
    `FRESH_CLUSTER#${"a".repeat(63)}`,
    "FRESH_CLUSTER#*"
  ]) {
    assert.throws(() => __test.exactKey({
      ...accepted,
      Key: { pk: { S: pk } }
    }, "prooftoact-release-controller"), /FRESH_CLUSTER_AWS_KEY_REJECTED/u);
  }
});

test("admin PutSecretValue is single-version and bounded", () => {
  assert.deepEqual(__test.adminSecretInput({
    clientRequestToken: COORDINATES.admin.versionId,
    secretString: ADMIN_VALUE
  }, COORDINATES.admin), {
    ClientRequestToken: COORDINATES.admin.versionId,
    SecretId: COORDINATES.admin.arn,
    SecretString: ADMIN_VALUE,
    VersionStages: ["AWSCURRENT"]
  });
  assert.throws(() => __test.adminSecretInput({
    clientRequestToken: "9".repeat(32),
    secretString: "wrong"
  }, COORDINATES.admin), /FRESH_CLUSTER_AWS_ADMIN_SECRET_REJECTED/u);
});
