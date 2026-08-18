import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  __test,
  approvedAccountBindingSha256,
  buildReleaseControlBootstrapPlan,
  serializeReleaseControlBootstrapPlan,
  validateBootstrapCensusReceipt,
  validateBootstrapCheckout,
  validateBootstrapTemplateBytes,
  validateBootstrapTemplateStructure
} from "../scripts/prepare-release-control-bootstrap.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PLANNER_BYTES = fs.readFileSync(
  path.join(ROOT, __test.PLANNER_PATH)
);
const TEMPLATE_BYTES = fs.readFileSync(
  path.join(ROOT, __test.TEMPLATE_PATH)
);
const SOURCE = PLANNER_BYTES.toString("utf8");
const ACCOUNT_ID = "123456789012";
const ACCOUNT_BINDING = approvedAccountBindingSha256(ACCOUNT_ID);
const ARTIFACT_BUCKET = "prooftoact-private-artifacts-123456789012";
const NOW = "2026-08-17T20:00:00.000Z";

function git(root, argv) {
  return execFileSync("/usr/bin/git", argv, {
    cwd: root,
    encoding: "utf8",
    env: {
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      LANG: "C",
      LC_ALL: "C",
      PATH: "/usr/bin:/bin"
    },
    stdio: ["ignore", "pipe", "pipe"]
  }).trim();
}

function fixture(t, { templateBytes = TEMPLATE_BYTES } = {}) {
  const parent = fs.mkdtempSync(
    path.join(fs.realpathSync(os.tmpdir()), "prooftoact-bootstrap-plan-")
  );
  const root = path.join(parent, "checkout");
  fs.mkdirSync(path.join(root, "scripts"), { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(root, "infra", "aws"), {
    recursive: true,
    mode: 0o700
  });
  fs.writeFileSync(path.join(root, __test.PLANNER_PATH), PLANNER_BYTES, {
    mode: 0o600
  });
  fs.writeFileSync(path.join(root, __test.TEMPLATE_PATH), templateBytes, {
    mode: 0o600
  });
  git(root, ["init", "--initial-branch=main"]);
  git(root, ["remote", "add", "origin", __test.OFFICIAL_ORIGIN]);
  git(root, ["add", "--all"]);
  git(root, [
    "-c", "user.name=ProofToAct Test",
    "-c", "user.email=prooftoact-test@example.invalid",
    "commit", "--no-gpg-sign", "-m", "sealed control plane fixture"
  ]);
  const identity = {
    commit: git(root, ["rev-parse", "HEAD"]),
    tree: git(root, ["rev-parse", "HEAD^{tree}"])
  };
  t.after(() => fs.rmSync(parent, { force: true, recursive: true }));
  return { identity, parent, root };
}

function census(overrides = {}) {
  const receipt = {
    schemaVersion: "prooftoact.release-control-bootstrap-census.v1",
    status: "ACCEPTED_READ_ONLY_CENSUS",
    evidenceLevel: "PROVIDER_READ_ONLY_CLAIM",
    readOnly: true,
    providerMutationPerformed: false,
    observedAt: "2026-08-17T19:58:00.000Z",
    expiresAt: "2026-08-17T20:05:00.000Z",
    region: "us-east-1",
    account: {
      approvedBindingSha256: ACCOUNT_BINDING,
      observedBindingSha256: ACCOUNT_BINDING,
      observedAccountId: ACCOUNT_ID,
      matchesApproved: true
    },
    gitHubOidcProvider: {
      exists: true,
      arn: `arn:aws:iam::${ACCOUNT_ID}:oidc-provider/` +
        "token.actions.githubusercontent.com",
      issuer: "https://token.actions.githubusercontent.com",
      audiencePresent: true
    },
    artifactBucket: {
      exists: true,
      name: ARTIFACT_BUCKET,
      region: "us-east-1",
      versioningStatus: "Enabled",
      defaultEncryptionEnabled: true,
      encryptionAlgorithm: "AES256",
      objectOwnership: "BucketOwnerEnforced",
      tlsOnlyPolicy: true,
      expectedBootstrapObjectKey: __test.exactBootstrapObjectKey(),
      publicAccessBlock: {
        blockPublicAcls: true,
        blockPublicPolicy: true,
        ignorePublicAcls: true,
        restrictPublicBuckets: true
      }
    },
    nameCollisionCensus: {
      checkedStackName: __test.STACK_NAME,
      checkedTableName: __test.CONTROL_TABLE_NAME,
      checkedBoundaryName: __test.BOUNDARY_NAME,
      checkedRoleNames: Object.values(__test.ROLE_NAMES).sort(),
      existingStack: false,
      existingTable: false,
      existingBoundary: false,
      existingRoleNames: [],
      unexpectedNamedResources: []
    },
    cost: {
      currency: "USD",
      observedCumulativeMicroUsd: 80_000,
      bootstrapReservationMicroUsd: 250_000,
      authorizedCumulativeCapMicroUsd: 20_000_000,
      projectedCumulativeMicroUsd: 330_000,
      withinAuthorizedCap: true
    }
  };
  return Object.assign(receipt, structuredClone(overrides));
}

function input(checkout, censusReceipt = census()) {
  return {
    censusReceipt,
    controlPlaneRoot: checkout.root,
    expectedAccountBindingSha256: ACCOUNT_BINDING,
    expectedArtifactBucketName: ARTIFACT_BUCKET,
    expectedControlPlaneCommit: checkout.identity.commit,
    expectedControlPlaneTree: checkout.identity.tree,
    now: NOW,
    requestedArtifactKey: __test.exactBootstrapObjectKey(),
    requestedRegion: "us-east-1"
  };
}

function clone(value) {
  return structuredClone(value);
}

function recursivelyFrozen(value) {
  if (value === null || typeof value !== "object") return true;
  return Object.isFrozen(value) && Object.values(value).every(recursivelyFrozen);
}

test("bootstrap plan is canonical, immutable, exact, and remains HOLD", (t) => {
  const checkout = fixture(t);
  const before = {
    commit: git(checkout.root, ["rev-parse", "HEAD"]),
    origin: git(checkout.root, ["remote", "get-url", "origin"]),
    status: git(checkout.root, ["status", "--porcelain=v1"]),
    tree: git(checkout.root, ["rev-parse", "HEAD^{tree}"])
  };
  const plan = buildReleaseControlBootstrapPlan(input(checkout));
  const second = buildReleaseControlBootstrapPlan(input(checkout));
  const after = {
    commit: git(checkout.root, ["rev-parse", "HEAD"]),
    origin: git(checkout.root, ["remote", "get-url", "origin"]),
    status: git(checkout.root, ["status", "--porcelain=v1"]),
    tree: git(checkout.root, ["rev-parse", "HEAD^{tree}"])
  };

  assert.deepEqual(after, before);
  assert.equal(plan.status, "HOLD_NOT_AUTHORIZED");
  assert.equal(plan.decision, "HOLD");
  assert.equal(plan.executionAuthorized, false);
  assert.equal(plan.providerMutationAuthorized, false);
  assert.equal(plan.directProviderExecutionSupported, false);
  assert.equal(plan.controlPlane.commit, checkout.identity.commit);
  assert.equal(plan.controlPlane.tree, checkout.identity.tree);
  assert.equal(plan.controlPlane.templateSha256,
    __test.REVIEWED_TEMPLATE_SHA256);
  assert.equal(plan.controlPlane.templateBytes, 84_981);
  assert.equal(
    plan.controlPlane.permissionsBoundaryPolicySha256,
    __test.REVIEWED_BOUNDARY_POLICY_SHA256
  );
  assert.equal(plan.templateUpload.key, __test.exactBootstrapObjectKey());
  assert.equal(plan.templateUpload.versionId, null);
  assert.equal(plan.templateUpload.exactBytesNoMinificationOrRewrite, true);
  assert.equal(plan.stack.stackName, __test.STACK_NAME);
  assert.deepEqual(plan.stack.capabilities, ["CAPABILITY_NAMED_IAM"]);
  assert.equal(plan.stack.expectedResourceCount, 10);
  assert.equal(plan.stack.expectedResources.length, 10);
  assert.equal(plan.stack.updateAllowed, false);
  assert.equal(plan.stack.automaticRetryAllowed, false);
  assert.equal(plan.spendEnvelope.bootstrapReservationMicroUsd, 250_000);
  assert.equal(plan.spendEnvelope.authorizedCumulativeCapMicroUsd, 20_000_000);
  assert.equal(plan.spendEnvelope.projectedCumulativeMicroUsd, 330_000);
  assert.equal(plan.rollbackAndRetention.retainedControlTable, true);
  assert.equal(plan.rollbackAndRetention.applicationDeploymentExcluded, true);
  assert.equal(recursivelyFrozen(plan), true);
  assert.deepEqual(plan, second);
  assert.deepEqual(
    serializeReleaseControlBootstrapPlan(plan),
    serializeReleaseControlBootstrapPlan(second)
  );
  const body = { ...plan };
  delete body.planBodySha256;
  assert.equal(plan.planBodySha256, __test.sha256(__test.canonicalBytes(body)));
});

test("checkout gate rejects dirty, linked-worktree, and aliased origin", (t) => {
  const dirty = fixture(t);
  fs.writeFileSync(path.join(dirty.root, "untracked.txt"), "dirty\n");
  assert.throws(
    () => validateBootstrapCheckout({
      controlPlaneRoot: dirty.root,
      expectedCommit: dirty.identity.commit,
      expectedTree: dirty.identity.tree
    }),
    /BOOTSTRAP_CHECKOUT_DIRTY_REJECTED/
  );

  const aliased = fixture(t);
  git(aliased.root, [
    "remote", "set-url", "origin", "git@github.com:Flash-Bri/prooftoact.git"
  ]);
  assert.throws(
    () => validateBootstrapCheckout({
      controlPlaneRoot: aliased.root,
      expectedCommit: aliased.identity.commit,
      expectedTree: aliased.identity.tree
    }),
    /BOOTSTRAP_OFFICIAL_ORIGIN_REJECTED/
  );

  const base = fixture(t);
  const linked = path.join(base.parent, "linked");
  git(base.root, ["worktree", "add", "-b", "linked-main", linked, "HEAD"]);
  assert.equal(fs.lstatSync(path.join(linked, ".git")).isFile(), true);
  assert.throws(
    () => validateBootstrapCheckout({
      controlPlaneRoot: linked,
      expectedCommit: base.identity.commit,
      expectedTree: base.identity.tree
    }),
    /BOOTSTRAP_STANDALONE_CHECKOUT_REJECTED/
  );
});

test("checkout gate binds exact future commit and tree without pinning them", (t) => {
  const checkout = fixture(t);
  const identity = validateBootstrapCheckout({
    controlPlaneRoot: checkout.root,
    expectedCommit: checkout.identity.commit,
    expectedTree: checkout.identity.tree
  });
  assert.equal(identity.commit, checkout.identity.commit);
  assert.equal(identity.tree, checkout.identity.tree);
  assert.throws(
    () => validateBootstrapCheckout({
      controlPlaneRoot: checkout.root,
      expectedCommit: "1".repeat(40),
      expectedTree: checkout.identity.tree
    }),
    /BOOTSTRAP_CHECKOUT_IDENTITY_REJECTED/
  );
  assert.throws(
    () => validateBootstrapCheckout({
      controlPlaneRoot: checkout.root,
      expectedCommit: checkout.identity.commit,
      expectedTree: "2".repeat(40)
    }),
    /BOOTSTRAP_CHECKOUT_IDENTITY_REJECTED/
  );
});

test("template gate rejects byte drift, minification, parameter drift, and resources drift", () => {
  const template = JSON.parse(TEMPLATE_BYTES.toString("utf8"));
  const minified = Buffer.from(JSON.stringify(template), "utf8");
  assert.notEqual(__test.sha256(minified), __test.REVIEWED_TEMPLATE_SHA256);
  assert.throws(
    () => validateBootstrapTemplateBytes(minified),
    /BOOTSTRAP_TEMPLATE_DIGEST_REJECTED/
  );
  const byteDrift = Buffer.concat([TEMPLATE_BYTES, Buffer.from("\n")]);
  assert.throws(
    () => validateBootstrapTemplateBytes(byteDrift),
    /BOOTSTRAP_TEMPLATE_DIGEST_REJECTED/
  );

  const parameterDrift = clone(template);
  delete parameterDrift.Parameters.ArtifactBucketName;
  assert.throws(
    () => validateBootstrapTemplateStructure(parameterDrift),
    /BOOTSTRAP_TEMPLATE_STRUCTURE_REJECTED/
  );
  const resourceDrift = clone(template);
  resourceDrift.Resources.Unexpected = { Type: "AWS::S3::Bucket" };
  assert.throws(
    () => validateBootstrapTemplateStructure(resourceDrift),
    /BOOTSTRAP_TEMPLATE_STRUCTURE_REJECTED/
  );
  const retentionDrift = clone(template);
  retentionDrift.Resources.ReleaseControlTable.DeletionPolicy = "Delete";
  assert.throws(
    () => validateBootstrapTemplateStructure(retentionDrift),
    /BOOTSTRAP_TEMPLATE_STRUCTURE_REJECTED/
  );
  const boundaryDrift = clone(template);
  boundaryDrift.Resources.CloudFormationPermissionsBoundary.Properties
    .PolicyDocument.Statement[0].Action.push("s3:DeleteObject");
  assert.throws(
    () => validateBootstrapTemplateStructure(boundaryDrift),
    /BOOTSTRAP_TEMPLATE_STRUCTURE_REJECTED/
  );
});

test("committed but drifted template still fails the checkout plan", (t) => {
  const template = JSON.parse(TEMPLATE_BYTES.toString("utf8"));
  const checkout = fixture(t, {
    templateBytes: Buffer.from(`${JSON.stringify(template)}\n`, "utf8")
  });
  assert.throws(
    () => buildReleaseControlBootstrapPlan(input(checkout)),
    /BOOTSTRAP_TEMPLATE_DIGEST_REJECTED/
  );
});

test("census gate rejects stale and contradictory read-only claims", () => {
  const stale = census({
    observedAt: "2026-08-17T19:40:00.000Z",
    expiresAt: "2026-08-17T19:50:00.000Z"
  });
  assert.throws(
    () => validateBootstrapCensusReceipt(stale, {
      expectedAccountBindingSha256: ACCOUNT_BINDING,
      expectedArtifactBucketName: ARTIFACT_BUCKET,
      expectedArtifactKey: __test.exactBootstrapObjectKey(),
      now: NOW
    }),
    /BOOTSTRAP_CENSUS_STALE_REJECTED/
  );

  const mutationClaim = census({
    readOnly: false,
    providerMutationPerformed: true
  });
  assert.throws(
    () => validateBootstrapCensusReceipt(mutationClaim, {
      expectedAccountBindingSha256: ACCOUNT_BINDING,
      expectedArtifactBucketName: ARTIFACT_BUCKET,
      expectedArtifactKey: __test.exactBootstrapObjectKey(),
      now: NOW
    }),
    /BOOTSTRAP_CENSUS_RECEIPT_REJECTED/
  );

  const unsafeBucket = census();
  unsafeBucket.artifactBucket.tlsOnlyPolicy = false;
  assert.throws(
    () => validateBootstrapCensusReceipt(unsafeBucket, {
      expectedAccountBindingSha256: ACCOUNT_BINDING,
      expectedArtifactBucketName: ARTIFACT_BUCKET,
      expectedArtifactKey: __test.exactBootstrapObjectKey(),
      now: NOW
    }),
    /BOOTSTRAP_CENSUS_BUCKET_REJECTED/
  );
});

test("census gate rejects every checked bootstrap name collision", () => {
  for (const [field, value] of [
    ["existingStack", true],
    ["existingTable", true],
    ["existingBoundary", true],
    ["existingRoleNames", ["ProofToActReleaseExecution"]],
    ["unexpectedNamedResources", ["unexpected"]]
  ]) {
    const receipt = census();
    receipt.nameCollisionCensus[field] = value;
    assert.throws(
      () => validateBootstrapCensusReceipt(receipt, {
        expectedAccountBindingSha256: ACCOUNT_BINDING,
        expectedArtifactBucketName: ARTIFACT_BUCKET,
        expectedArtifactKey: __test.exactBootstrapObjectKey(),
        now: NOW
      }),
      /BOOTSTRAP_CENSUS_COLLISION_REJECTED/
    );
  }
});

test("census cost gate enforces the $0.25 reservation inside one $20 ledger", () => {
  const overCap = census();
  overCap.cost.observedCumulativeMicroUsd = 19_900_001;
  overCap.cost.projectedCumulativeMicroUsd = 20_150_001;
  overCap.cost.withinAuthorizedCap = false;
  assert.throws(
    () => validateBootstrapCensusReceipt(overCap, {
      expectedAccountBindingSha256: ACCOUNT_BINDING,
      expectedArtifactBucketName: ARTIFACT_BUCKET,
      expectedArtifactKey: __test.exactBootstrapObjectKey(),
      now: NOW
    }),
    /BOOTSTRAP_CENSUS_COST_REJECTED/
  );

  const expandedCap = census();
  expandedCap.cost.authorizedCumulativeCapMicroUsd = 21_000_000;
  assert.throws(
    () => validateBootstrapCensusReceipt(expandedCap, {
      expectedAccountBindingSha256: ACCOUNT_BINDING,
      expectedArtifactBucketName: ARTIFACT_BUCKET,
      expectedArtifactKey: __test.exactBootstrapObjectKey(),
      now: NOW
    }),
    /BOOTSTRAP_CENSUS_COST_REJECTED/
  );

  const reducedReservation = census();
  reducedReservation.cost.bootstrapReservationMicroUsd = 1;
  reducedReservation.cost.projectedCumulativeMicroUsd = 80_001;
  assert.throws(
    () => validateBootstrapCensusReceipt(reducedReservation, {
      expectedAccountBindingSha256: ACCOUNT_BINDING,
      expectedArtifactBucketName: ARTIFACT_BUCKET,
      expectedArtifactKey: __test.exactBootstrapObjectKey(),
      now: NOW
    }),
    /BOOTSTRAP_CENSUS_COST_REJECTED/
  );
});

test("plan rejects wrong key, region, and approved-account binding", (t) => {
  const checkout = fixture(t);
  const wrongKey = input(checkout);
  wrongKey.requestedArtifactKey = "gate2/control-plane-bootstrap/wrong.json";
  assert.throws(
    () => buildReleaseControlBootstrapPlan(wrongKey),
    /BOOTSTRAP_PLAN_ARTIFACT_KEY_REJECTED/
  );

  const wrongRegion = input(checkout);
  wrongRegion.requestedRegion = "us-west-2";
  assert.throws(
    () => buildReleaseControlBootstrapPlan(wrongRegion),
    /BOOTSTRAP_PLAN_REGION_REJECTED/
  );

  const receiptWrongRegion = input(checkout);
  receiptWrongRegion.censusReceipt.region = "us-west-2";
  assert.throws(
    () => buildReleaseControlBootstrapPlan(receiptWrongRegion),
    /BOOTSTRAP_CENSUS_RECEIPT_REJECTED/
  );

  const wrongAccount = input(checkout);
  wrongAccount.expectedAccountBindingSha256 = "f".repeat(64);
  assert.throws(
    () => buildReleaseControlBootstrapPlan(wrongAccount),
    /BOOTSTRAP_CENSUS_ACCOUNT_REJECTED/
  );
});

test("planner has no provider/network client and child process is read-only Git", () => {
  assert.doesNotMatch(SOURCE, /@aws-sdk|from\s+["']aws-sdk/u);
  assert.doesNotMatch(
    SOURCE,
    /from\s+["']node:(?:http|https|net|tls|dns|dgram)["']/u
  );
  assert.doesNotMatch(SOURCE, /\bfetch\s*\(/u);
  assert.equal((SOURCE.match(/execFileSync\s*\(/gu) ?? []).length, 1);
  assert.match(SOURCE, /execFileSync\(\s*"\/usr\/bin\/git"/u);
  const firstAndSecond = __test.ALLOWED_GIT_COMMANDS.map((argv) =>
    argv.slice(0, 2).join(" ")
  );
  for (const forbidden of [
    "add",
    "apply",
    "checkout",
    "clean",
    "commit",
    "config",
    "fetch",
    "merge",
    "push",
    "reset",
    "restore",
    "switch",
    "tag",
    "worktree add"
  ]) {
    assert.equal(firstAndSecond.includes(forbidden), false, forbidden);
  }
  assert.deepEqual(
    __test.ALLOWED_GIT_COMMANDS.find((argv) => argv[0] === "remote"),
    ["remote", "get-url", "origin"]
  );
  const cli = execFileSync(process.execPath, [
    path.join(ROOT, __test.PLANNER_PATH)
  ], {
    cwd: ROOT,
    encoding: "utf8",
    env: { PATH: "/usr/bin:/bin" },
    stdio: ["ignore", "pipe", "pipe"]
  });
  assert.equal(
    cli,
    "HOLD:RELEASE_CONTROL_BOOTSTRAP_PLANNER_IS_LOCAL_ONLY_AND_NEVER_AUTHORIZES_PROVIDER_EXECUTION\n"
  );
});
