import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SOURCE_LOCK_PATH = path.join(
  ROOT, "scripts/lib/private-recovery-source-lock.py"
);
const SOURCE_LOCK = fs.readFileSync(SOURCE_LOCK_PATH, "utf8");
const EXPECTED_COMMIT = "a".repeat(40);
const EXPECTED_TREE = "b".repeat(40);
const CALLER_COMMIT = "c".repeat(40);
const ZERO = "0".repeat(40);
const REVIEWED_COMMIT = "caf417dd84d899c7407e5ed12f56b60f1b74d32a";
const REVIEWED_TREE = "b01bf525dd47eb7ad6ed412e9557010289c6836b";
const AUDIENCE = "prooftoact-private-recovery-source-lock-v1";
const LANES = Object.freeze({
  deploy: Object.freeze({
    environment: "aws-private-recovery-deploy",
    workflow: "ProofToAct Private Recovery Deploy",
    caller: "prooftoact-private-recovery-deploy.yml",
    sealed: "prooftoact-sealed-private-recovery-deploy.yml"
  }),
  evidence: Object.freeze({
    environment: "aws-private-recovery-evidence",
    workflow: "ProofToAct Private Recovery Evidence",
    caller: "prooftoact-private-recovery-evidence.yml",
    sealed: "prooftoact-sealed-private-recovery-evidence.yml"
  }),
  query: Object.freeze({
    environment: "aws-private-recovery-query",
    workflow: "ProofToAct Private Recovery Query",
    caller: "prooftoact-private-recovery-query.yml",
    sealed: "prooftoact-sealed-private-recovery-query.yml"
  }),
  "secret-seal": Object.freeze({
    environment: "aws-private-recovery-deploy",
    workflow: "ProofToAct Private Recovery Secret Seal",
    caller: "prooftoact-private-recovery-secret-seal.yml",
    sealed: "prooftoact-sealed-private-recovery-secret-seal.yml"
  }),
  teardown: Object.freeze({
    environment: "aws-private-recovery-teardown",
    workflow: "ProofToAct Private Recovery Teardown",
    caller: "prooftoact-private-recovery-teardown.yml",
    sealed: "prooftoact-sealed-private-recovery-teardown.yml"
  })
});

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

function tokenResponse(lane, overrides = {}, { payloadSource } = {}) {
  const identity = LANES[lane];
  assert(identity, `unknown lane ${lane}`);
  const now = Math.floor(Date.now() / 1000);
  const prefix = "Flash-Bri/prooftoact/.github/workflows/";
  const payload = {
    iss: "https://token.actions.githubusercontent.com",
    aud: AUDIENCE,
    repository: "Flash-Bri/prooftoact",
    repository_id: "1317716765",
    repository_owner: "Flash-Bri",
    repository_owner_id: "252500266",
    repository_visibility: "public",
    ref: "refs/heads/main",
    ref_type: "branch",
    ref_protected: "true",
    environment: identity.environment,
    sub: "repo:Flash-Bri@252500266/prooftoact@1317716765:" +
      `environment:${identity.environment}`,
    workflow: identity.workflow,
    workflow_ref: `${prefix}${identity.caller}@refs/heads/main`,
    workflow_sha: CALLER_COMMIT,
    job_workflow_ref: `${prefix}${identity.sealed}@${EXPECTED_COMMIT}`,
    job_workflow_sha: EXPECTED_COMMIT,
    event_name: "workflow_dispatch",
    runner_environment: "github-hosted",
    sha: CALLER_COMMIT,
    jti: "123e4567-e89b-42d3-a456-426614174000",
    iat: now - 5,
    nbf: now - 5,
    exp: now + 300,
    ...overrides
  };
  const payloadBytes = payloadSource ?? JSON.stringify(payload);
  return JSON.stringify({
    value: [
      base64url(JSON.stringify({ alg: "RS256", kid: "fixture", typ: "JWT" })),
      base64url(payloadBytes),
      base64url("fixture-signature")
    ].join(".")
  });
}

function runSourceLock(mode, args, input = "") {
  return spawnSync(
    "/usr/bin/python3",
    ["-I", "-S", "-B", SOURCE_LOCK_PATH, mode, ...args],
    { cwd: ROOT, encoding: "utf8", input }
  );
}

function workflow(name) {
  return fs.readFileSync(path.join(ROOT, ".github/workflows", name), "utf8");
}

function embeddedSourceLockValidator(contents) {
  const match = contents.match(
    /<<'PRIVATE_RECOVERY_SOURCE_LOCK_PY'\n([\s\S]*?)\n {10}PRIVATE_RECOVERY_SOURCE_LOCK_PY/u
  );
  assert(match, "missing embedded private-recovery source-lock validator");
  return `${match[1].split("\n").map((line) =>
    line.startsWith("          ") ? line.slice(10) : line).join("\n")}\n`;
}

function assertImmutableSourceLockContract(contents) {
  const sourceLock = contents.indexOf(
    "name: Bind immutable reusable source before protected material"
  );
  const checkout = contents.indexOf("uses: actions/checkout@");
  const firstSecret = contents.indexOf("${{ secrets.");
  assert(sourceLock >= 0 && checkout > sourceLock && firstSecret > sourceLock);
  assert.match(contents, /ACTIONS_ID_TOKEN_REQUEST_URL/u);
  assert.match(contents, /--config -/u);
  assert.match(contents, /if ! oidc_response="\$\(/u);
  assert.match(contents,
    /test "\$\(git rev-parse HEAD\)" = "\$AUTHORITY_COMMIT"/u);
  assert.match(contents,
    /test "\$\(git rev-parse HEAD\^\{tree\}\)" = "\$AUTHORITY_TREE"/u);
  assert.doesNotMatch(contents,
    /--header[\s\S]*ACTIONS_ID_TOKEN_REQUEST_TOKEN/u);
  const nextStep = contents.indexOf("\n      - name:", sourceLock + 20);
  const sourceLockStep = contents.slice(sourceLock, nextStep);
  assert.match(sourceLockStep, /set \+x/u);
  assert.equal((sourceLockStep.match(/\/usr\/bin\/env -i/gu) ?? []).length, 3);
  assert.equal((sourceLockStep.match(/\/usr\/bin\/python3 -I -S -B -c/gu) ?? [])
    .length, 2);
  assert.match(sourceLockStep, /printf '%s' "\$oidc_response" \|/u);
  assert.doesNotMatch(sourceLockStep,
    /(?:mktemp|RUNNER_TEMP|GITHUB_OUTPUT|upload-artifact|oidc-(?:token|response|payload)\.)/u);
}

test("all sealed lanes bind their GitHub-issued reusable identity before secrets", () => {
  for (const [lane, identity] of Object.entries(LANES)) {
    const sealed = workflow(identity.sealed);
    assertImmutableSourceLockContract(sealed);
    assert.equal(embeddedSourceLockValidator(sealed), SOURCE_LOCK, lane);
    assert.match(sealed, new RegExp(`SOURCE_LOCK_LANE: ${lane}`, "u"));
    assert.match(sealed,
      /authority_commit:\n\s+required: true\n\s+type: string/u);
    assert.match(sealed,
      /authority_tree:\n\s+required: true\n\s+type: string/u);
    assert.doesNotMatch(sealed, /REVIEWED_RUNTIME_(?:COMMIT|TREE)/u);
  }
});

test("all callers pin one reviewed Commit A and its exact tree", () => {
  for (const identity of Object.values(LANES)) {
    const caller = workflow(identity.caller);
    assert.match(caller, /permissions: \{\}/u);
    assert.match(caller,
      /permissions:\n      contents: read\n      id-token: write/u);
    assert.match(caller, new RegExp(
      `uses: Flash-Bri/prooftoact/\\.github/workflows/${identity.sealed.replace(
        ".", "\\."
      )}@${REVIEWED_COMMIT}`, "u"
    ));
    assert.match(caller, new RegExp(
      `authority_commit: "${REVIEWED_COMMIT}"`, "u"
    ));
    assert.match(caller, new RegExp(
      `authority_tree: "${REVIEWED_TREE}"`, "u"
    ));
    assert.doesNotMatch(caller, /pull_request_target|repository_dispatch/u);

    const committedSource = spawnSync(
      "git", ["show", `${REVIEWED_COMMIT}:.github/workflows/${identity.sealed}`],
      { cwd: ROOT, encoding: "utf8" }
    );
    assert.equal(committedSource.status, 0, committedSource.stderr);
    assert.equal(committedSource.stdout, workflow(identity.sealed), identity.sealed);
  }
  assert.equal(spawnSync(
    "git", ["show", "-s", "--format=%T", REVIEWED_COMMIT],
    { cwd: ROOT, encoding: "utf8" }
  ).stdout.trim(), REVIEWED_TREE);
});

test("source-lock endpoint accepts only the bounded GitHub HTTPS endpoint", () => {
  const endpoint = "https://pipelines.actions.githubusercontent.com/" +
    "fixture/_apis/distributedtask/hubs/build/plans/plan/jobs/job/" +
    "idtoken?api-version=2.0";
  const accepted = runSourceLock("--validate-endpoint", [AUDIENCE, endpoint]);
  assert.equal(accepted.status, 0, accepted.stderr);
  assert.equal(accepted.stdout.trim().endsWith(`&audience=${AUDIENCE}`), true);
  for (const rejectedEndpoint of [
    endpoint.replace("https://", "http://"),
    "https://example.invalid/x?api-version=2.0",
    "https://user" +
      "@pipelines.actions.githubusercontent.com/x?api-version=2.0",
    "https://pipelines.actions.githubusercontent.com/x?api-version=2.0&extra=1",
    "https://pipelines.actions.githubusercontent.com/x?api-version=1.0",
    "https://pipelines.actions.githubusercontent.com/x/../y?api-version=2.0"
  ]) {
    const rejected = runSourceLock("--validate-endpoint", [
      AUDIENCE, rejectedEndpoint
    ]);
    assert.notEqual(rejected.status, 0, rejectedEndpoint);
    assert.equal(rejected.stderr.trim(),
      "PRIVATE_RECOVERY_SOURCE_LOCK_REJECTED");
  }
});

test("source lock accepts the exact identity of every private recovery lane", () => {
  for (const lane of Object.keys(LANES)) {
    const accepted = runSourceLock("--validate-token", [
      AUDIENCE, lane, EXPECTED_COMMIT, EXPECTED_TREE
    ], tokenResponse(lane));
    assert.equal(accepted.status, 0, `${lane}: ${accepted.stderr}`);
    assert.equal(accepted.stdout.trim(),
      `SOURCE_LOCKED:${lane}:${EXPECTED_COMMIT}:${EXPECTED_TREE}`);
  }
});

test("source lock rejects identity, time, structure, and coordinate drift", () => {
  const lane = "query";
  const identity = LANES[lane];
  const variants = [
    tokenResponse(lane, { repository: "other/repository" }),
    tokenResponse(lane, { ref: "refs/heads/feature" }),
    tokenResponse(lane, { environment: "aws-private-recovery-deploy" }),
    tokenResponse(lane, { workflow: "ProofToAct Private Recovery Deploy" }),
    tokenResponse(lane, {
      workflow_ref: "Flash-Bri/prooftoact/.github/workflows/" +
        `${identity.caller}@refs/heads/feature`
    }),
    tokenResponse(lane, {
      job_workflow_ref: "Flash-Bri/prooftoact/.github/workflows/" +
        `other.yml@${EXPECTED_COMMIT}`
    }),
    tokenResponse(lane, {
      job_workflow_ref: "Flash-Bri/prooftoact/.github/workflows/" +
        `${identity.sealed}@${"d".repeat(40)}`
    }),
    tokenResponse(lane, { job_workflow_sha: "d".repeat(40) }),
    tokenResponse(lane, { workflow_sha: "d".repeat(40) }),
    tokenResponse(lane, { ref_protected: "false" }),
    tokenResponse(lane, { aud: "sts.amazonaws.com" }),
    tokenResponse(lane, { iat: "not-a-number" }),
    tokenResponse(lane, { exp: Math.floor(Date.now() / 1000) - 1 }),
    tokenResponse(lane, { extra: { nested: true } }),
    JSON.stringify({ value: "malformed" })
  ];
  const missingPayload = JSON.parse(Buffer.from(
    JSON.parse(tokenResponse(lane)).value.split(".")[1], "base64url"
  ).toString("utf8"));
  delete missingPayload.job_workflow_ref;
  variants.push(tokenResponse(lane, {}, {
    payloadSource: JSON.stringify(missingPayload)
  }));
  const duplicatePayload = JSON.stringify(missingPayload).replace(/\}$/u,
    `,"job_workflow_ref":"Flash-Bri/prooftoact/.github/workflows/` +
    `${identity.sealed}@${EXPECTED_COMMIT}",` +
    `"job_workflow_ref":"Flash-Bri/prooftoact/.github/workflows/` +
    `${identity.sealed}@${EXPECTED_COMMIT}"}`);
  variants.push(tokenResponse(lane, {}, { payloadSource: duplicatePayload }));

  for (const response of variants) {
    const rejected = runSourceLock("--validate-token", [
      AUDIENCE, lane, EXPECTED_COMMIT, EXPECTED_TREE
    ], response);
    assert.notEqual(rejected.status, 0);
    assert.equal(rejected.stderr.trim(),
      "PRIVATE_RECOVERY_SOURCE_LOCK_REJECTED");
  }
  for (const [badLane, badCommit, badTree] of [
    ["other", EXPECTED_COMMIT, EXPECTED_TREE],
    [lane, ZERO, EXPECTED_TREE],
    [lane, EXPECTED_COMMIT, "not-a-tree"]
  ]) {
    const rejected = runSourceLock("--validate-token", [
      AUDIENCE, badLane, badCommit, badTree
    ], tokenResponse(lane));
    assert.notEqual(rejected.status, 0);
  }
});

test("source-lock contract fails closed if dispatch or source guards are removed", () => {
  const sealed = workflow(LANES.deploy.sealed);
  for (const mutation of [
    sealed.replace("if ! oidc_response=\"$(", "oidc_response=\"$("),
    sealed.replace(
      'test "$(git rev-parse HEAD)" = "$AUTHORITY_COMMIT"', "true"
    ),
    sealed.replace(
      'test "$(git rev-parse HEAD^{tree})" = "$AUTHORITY_TREE"', "true"
    )
  ]) {
    assert.throws(() => assertImmutableSourceLockContract(mutation));
  }
});
