"use strict";

async function handler(event) {
  if (
    !event ||
    typeof event !== "object" ||
    Object.keys(event).sort().join("\n") !== "mode" ||
    event.mode !== "status"
  ) {
    throw new Error("AUTHORITY_REQUEST_REJECTED");
  }
  return {
    schemaVersion: "tideproof.aws-authority-boundary.v1",
    status: "UNKNOWN_DO_NOT_ACT",
    reason: "COCKROACH_AUTHORITY_NOT_CONNECTED_IN_GATE_TWO",
    sourceCommit: process.env.SOURCE_COMMIT,
    configDigest: process.env.CONFIG_DIGEST,
    treeDigest: process.env.TREE_DIGEST,
    packageLockDigest: process.env.PACKAGE_LOCK_DIGEST,
    authoritySourceDigest: process.env.AUTHORITY_SOURCE_DIGEST,
    authorityArtifactDigest: process.env.AUTHORITY_ARTIFACT_DIGEST,
    authorityTransferred: false,
    requiresFreshAuthorization: true,
    modelAccess: false
  };
}

exports.handler = handler;
