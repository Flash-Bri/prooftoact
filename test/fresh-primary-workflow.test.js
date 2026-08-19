import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CALLER = fs.readFileSync(path.join(
  ROOT, ".github/workflows/prooftoact-fresh-primary.yml"
), "utf8");
const SEALED = fs.readFileSync(path.join(
  ROOT, ".github/workflows/prooftoact-sealed-fresh-primary.yml"
), "utf8");
const TEMPLATE = JSON.parse(fs.readFileSync(path.join(
  ROOT, "infra/aws/fresh-primary-bootstrap-role-stack.json"
), "utf8"));
const SOURCE_LOCK_VALIDATOR_PATH = path.join(
  ROOT, "scripts/lib/fresh-primary-source-lock.py"
);
const SOURCE_LOCK_VALIDATOR = fs.existsSync(SOURCE_LOCK_VALIDATOR_PATH)
  ? fs.readFileSync(SOURCE_LOCK_VALIDATOR_PATH, "utf8")
  : "";
const PIN = "b8f993a4a9a898673c89dbd8218ec7eb591f1f10";
const PIN_TREE = "4615e7bea235f1c4ddf7f680d125cad6d355fecf";
const EXPECTED_COMMIT = "a".repeat(40);
const CALLER_COMMIT = "b".repeat(40);
const EXPECTED_TREE = "c".repeat(40);
const SOURCE_LOCK_AUDIENCE =
  "prooftoact-fresh-primary-source-lock-v1";

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

function tokenResponse(overrides = {}, { payloadSource } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: "https://token.actions.githubusercontent.com",
    aud: SOURCE_LOCK_AUDIENCE,
    repository: "Flash-Bri/prooftoact",
    repository_id: "1317716765",
    repository_owner: "Flash-Bri",
    repository_owner_id: "252500266",
    repository_visibility: "public",
    ref: "refs/heads/main",
    ref_type: "branch",
    ref_protected: "true",
    environment: "aws-release-database-bootstrap",
    sub: "repo:Flash-Bri@252500266/prooftoact@1317716765:" +
      "environment:aws-release-database-bootstrap",
    workflow: "ProofToAct Fresh Cluster And Primary",
    workflow_ref: "Flash-Bri/prooftoact/.github/workflows/" +
      "prooftoact-fresh-primary.yml@refs/heads/main",
    workflow_sha: CALLER_COMMIT,
    job_workflow_ref: "Flash-Bri/prooftoact/.github/workflows/" +
      `prooftoact-sealed-fresh-primary.yml@${EXPECTED_COMMIT}`,
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
    [SOURCE_LOCK_VALIDATOR_PATH, mode, ...args],
    { cwd: ROOT, encoding: "utf8", input }
  );
}

function embeddedSourceLockValidator(workflow) {
  const match = workflow.match(
    /<<'FRESH_PRIMARY_SOURCE_LOCK_PY'\n([\s\S]*?)\n {10}FRESH_PRIMARY_SOURCE_LOCK_PY/u
  );
  assert(match, "missing embedded source-lock validator");
  return `${match[1].split("\n").map((line) =>
    line.startsWith("          ") ? line.slice(10) : line).join("\n")}\n`;
}

function assertImmutableSourceLockContract(workflow) {
  const sourceLock = workflow.indexOf(
    "name: Bind immutable reusable source before protected material"
  );
  const checkout = workflow.indexOf("name: Check out exact control plane");
  const firstSecret = workflow.indexOf("${{ secrets.");
  assert(sourceLock >= 0 && checkout > sourceLock && firstSecret > sourceLock);
  assert.match(workflow,
    /ACTIONS_ID_TOKEN_REQUEST_URL/u);
  assert.match(workflow,
    /--config -/u);
  assert.match(workflow,
    /if ! oidc_response="\$\(/u);
  assert.match(workflow,
    /test "\$\(git rev-parse HEAD\)" = "\$AUTHORITY_COMMIT"/u);
  assert.match(workflow,
    /test "\$\(git rev-parse HEAD\^\{tree\}\)" = "\$AUTHORITY_TREE"/u);
  assert.doesNotMatch(workflow, /--header[\s\S]*ACTIONS_ID_TOKEN_REQUEST_TOKEN/u);
  const sourceLockStep = workflow.slice(sourceLock, workflow.indexOf(
    "- name: Validate protected immutable coordinates", sourceLock
  ));
  assert.match(sourceLockStep, /set \+x/u);
  assert.match(sourceLockStep, /--config -/u);
  assert.equal((sourceLockStep.match(/\/usr\/bin\/env -i/gu) ?? []).length, 3);
  assert.equal((sourceLockStep.match(/\/usr\/bin\/python3 -I -S -B -c/gu) ?? [])
    .length, 2);
  assert.match(sourceLockStep,
    /printf '%s' "\$oidc_response" \|/u);
  assert.doesNotMatch(sourceLockStep,
    /(?:mktemp|RUNNER_TEMP|GITHUB_OUTPUT|upload-artifact|oidc-(?:token|response|payload)\.)/u);
}

test("fresh-primary caller is main-only and pins immutable authority bytes", () => {
  assert.match(CALLER,
    /^name: ProofToAct Fresh Cluster And Primary$/mu);
  assert.match(CALLER, /\non:\n  workflow_dispatch:\n/u);
  assert.match(CALLER,
    /if: \$\{\{ github\.ref == 'refs\/heads\/main' \}\}/u);
  assert.match(CALLER, /permissions:\n  contents: read\n/u);
  assert.match(CALLER,
    /sealed-fresh-cluster-and-primary:[\s\S]*?permissions:\n      contents: read\n      id-token: write\n/u);
  assert.match(CALLER, new RegExp(
    "uses: Flash-Bri/prooftoact/\\.github/workflows/" +
    `prooftoact-sealed-fresh-primary\\.yml@${PIN}`, "u"
  ));
  assert.match(CALLER,
    /test "\$\(git rev-parse HEAD\)" = "\$EXPECTED_COMMIT"/u);
  assert.match(CALLER, new RegExp(`EXPECTED_COMMIT: ${PIN}`, "u"));
  assert.match(CALLER, new RegExp(`EXPECTED_TREE: ${PIN_TREE}`, "u"));
  assert.match(CALLER,
    /test "\$authority_tree" = "\$EXPECTED_TREE"/u);
  assert.match(CALLER,
    /test -z "\$\(git status --porcelain=v1 --untracked-files=all\)"/u);
  assert.doesNotMatch(CALLER, /environment:/u);
  assert.doesNotMatch(CALLER, /secrets:/u);
});

test("sealed workflow owns the protected environment and exact OIDC job", () => {
  assert.match(SEALED, /\non:\n  workflow_call:\n/u);
  assert.match(SEALED,
    /sealed-fresh-cluster-and-primary:[\s\S]*?permissions:\n      contents: read\n      id-token: write\n    environment: aws-release-database-bootstrap/u);
  assert.equal((SEALED.match(/environment: aws-release-database-bootstrap/gu)
    ?? []).length, 1);
  assert.equal((SEALED.match(/id-token: write/gu) ?? []).length, 1);
});

test("protected environment pins approval bytes to the actual caller identity", () => {
  assert.match(SEALED,
    /APPROVAL_SHA256: \$\{\{ vars\.PROOFTOACT_FRESH_CLUSTER_APPROVAL_SHA256 \}\}/u);
  assert.match(SEALED,
    /CALLER_WORKFLOW_REF: \$\{\{ github\.workflow_ref \}\}/u);
  assert.match(SEALED,
    /CALLER_WORKFLOW_SHA: \$\{\{ github\.workflow_sha \}\}/u);
  assert.equal((SEALED.match(
    /HUMAN_AUTHORIZATION_SIGNER_SHA256: \$\{\{ vars\.PROOFTOACT_HUMAN_AUTHORIZATION_SIGNER_SHA256 \}\}/gu
  ) ?? []).length, 3);
  assert.match(SEALED,
    /\[\[ "\$HUMAN_AUTHORIZATION_SIGNER_SHA256" =~ \^\[0-9a-f\]\{64\}\$ \]\]/u);
  assert.match(SEALED,
    /--approval-sha256 "\$APPROVAL_SHA256"/u);
  assert.match(SEALED,
    /--caller-workflow-ref "\$CALLER_WORKFLOW_REF"/u);
  assert.match(SEALED,
    /--caller-workflow-sha "\$CALLER_WORKFLOW_SHA"/u);
  assert.equal((SEALED.match(/--approval-sha256/gu) ?? []).length, 2);
  assert.equal((SEALED.match(
    /--human-authorization-signer-sha256 "\$HUMAN_AUTHORIZATION_SIGNER_SHA256"/gu
  ) ?? []).length, 2);
  assert.doesNotMatch(SEALED,
    /workflow_call:[\s\S]{0,600}approval_sha256:/u);
});

test("standalone trust binds top-level workflow and reusable byte identity", () => {
  const condition = TEMPLATE.Resources.FreshPrimaryBootstrapRole.Properties
    .AssumeRolePolicyDocument.Statement[0].Condition.StringEquals;
  assert.equal(condition["token.actions.githubusercontent.com:workflow"],
    "ProofToAct Fresh Cluster And Primary");
  assert.equal(condition[
    "token.actions.githubusercontent.com:job_workflow_ref"
  ], "Flash-Bri/prooftoact/.github/workflows/" +
    `prooftoact-sealed-fresh-primary.yml@${PIN}`);
  assert.equal(condition["token.actions.githubusercontent.com:environment"],
    "aws-release-database-bootstrap");
  assert.equal(condition["token.actions.githubusercontent.com:ref"],
    "refs/heads/main");
});

test("immutable reusable binds its own GitHub-issued source before secrets or checkout", () => {
  assertImmutableSourceLockContract(SEALED);
  assert.equal(embeddedSourceLockValidator(SEALED), SOURCE_LOCK_VALIDATOR);
  assert.equal(
    SEALED.indexOf("name: Bind immutable reusable source before protected material") <
      SEALED.indexOf("${{ secrets."),
    true
  );
});

test("source-lock endpoint accepts only the bounded GitHub HTTPS token endpoint", () => {
  const valid = runSourceLock("--validate-endpoint", [
    SOURCE_LOCK_AUDIENCE,
    "https://pipelines.actions.githubusercontent.com/" +
      "fixture/_apis/distributedtask/hubs/build/plans/plan/jobs/job/" +
      "idtoken?api-version=2.0"
  ]);
  assert.equal(valid.status, 0, valid.stderr);
  assert.equal(valid.stdout.trim().endsWith(
    `&audience=${SOURCE_LOCK_AUDIENCE}`), true);
  for (const endpoint of [
    "http://pipelines.actions.githubusercontent.com/x?api-version=2.0",
    "https://example.invalid/x?api-version=2.0",
    "https://user" +
      "@pipelines.actions.githubusercontent.com/x?api-version=2.0",
    "https://pipelines.actions.githubusercontent.com/x?api-version=2.0&extra=1",
    "https://pipelines.actions.githubusercontent.com/x?api-version=1.0"
  ]) {
    const rejected = runSourceLock("--validate-endpoint", [
      SOURCE_LOCK_AUDIENCE,
      endpoint
    ]);
    assert.notEqual(rejected.status, 0, endpoint);
    assert.equal(rejected.stderr.trim(),
      "FRESH_PRIMARY_SOURCE_LOCK_REJECTED");
  }
});

test("source-lock token accepts only exact reusable identity and bounded claims", () => {
  const accepted = runSourceLock("--validate-token", [
    SOURCE_LOCK_AUDIENCE,
    EXPECTED_COMMIT,
    EXPECTED_TREE,
    CALLER_COMMIT
  ], tokenResponse());
  assert.equal(accepted.status, 0, accepted.stderr);
  assert.equal(accepted.stdout.trim(),
    `SOURCE_LOCKED:${EXPECTED_COMMIT}:${EXPECTED_TREE}`);
  const optionalRefProtected = tokenResponse({ ref_protected: undefined });
  const optionalPayload = JSON.parse(Buffer.from(
    JSON.parse(optionalRefProtected).value.split(".")[1], "base64url"
  ).toString("utf8"));
  delete optionalPayload.ref_protected;
  const optionalAccepted = runSourceLock("--validate-token", [
    SOURCE_LOCK_AUDIENCE,
    EXPECTED_COMMIT,
    EXPECTED_TREE,
    CALLER_COMMIT
  ], tokenResponse({}, { payloadSource: JSON.stringify(optionalPayload) }));
  assert.equal(optionalAccepted.status, 0, optionalAccepted.stderr);

  const variants = [
    tokenResponse({ repository: "other/repository" }),
    tokenResponse({ ref: "refs/heads/feature" }),
    tokenResponse({
      job_workflow_ref: "Flash-Bri/prooftoact/.github/workflows/" +
        `other.yml@${EXPECTED_COMMIT}`
    }),
    tokenResponse({
      job_workflow_ref: "Flash-Bri/prooftoact/.github/workflows/" +
        `prooftoact-sealed-fresh-primary.yml@${"d".repeat(40)}`
    }),
    tokenResponse({ job_workflow_sha: "d".repeat(40) }),
    tokenResponse({ ref_protected: "false" }),
    tokenResponse({ aud: "sts.amazonaws.com" }),
    tokenResponse({ iat: "not-a-number" }),
    JSON.stringify({ value: "malformed" })
  ];
  const missing = JSON.parse(tokenResponse());
  const missingPayload = JSON.parse(
    Buffer.from(missing.value.split(".")[1], "base64url").toString("utf8")
  );
  delete missingPayload.job_workflow_ref;
  variants.push(tokenResponse({}, {
    payloadSource: JSON.stringify(missingPayload)
  }));
  const missingJobSha = JSON.parse(
    Buffer.from(JSON.parse(tokenResponse()).value.split(".")[1], "base64url")
      .toString("utf8")
  );
  delete missingJobSha.job_workflow_sha;
  variants.push(tokenResponse({}, {
    payloadSource: JSON.stringify(missingJobSha)
  }));
  const duplicatePayload = JSON.stringify(missingPayload).replace(/\}$/u,
    `,"job_workflow_ref":"Flash-Bri/prooftoact/.github/workflows/` +
    `prooftoact-sealed-fresh-primary.yml@${EXPECTED_COMMIT}",` +
    `"job_workflow_ref":"Flash-Bri/prooftoact/.github/workflows/` +
    `prooftoact-sealed-fresh-primary.yml@${EXPECTED_COMMIT}"}`);
  variants.push(tokenResponse({}, { payloadSource: duplicatePayload }));

  for (const response of variants) {
    const rejected = runSourceLock("--validate-token", [
      SOURCE_LOCK_AUDIENCE,
      EXPECTED_COMMIT,
      EXPECTED_TREE,
      CALLER_COMMIT
    ], response);
    assert.notEqual(rejected.status, 0);
    assert.equal(rejected.stderr.trim(),
      "FRESH_PRIMARY_SOURCE_LOCK_REJECTED");
  }
  const wrongExpectedCaller = runSourceLock("--validate-token", [
    SOURCE_LOCK_AUDIENCE,
    EXPECTED_COMMIT,
    EXPECTED_TREE,
    "d".repeat(40)
  ], tokenResponse());
  assert.notEqual(wrongExpectedCaller.status, 0);
  assert.equal(wrongExpectedCaller.stderr.trim(),
    "FRESH_PRIMARY_SOURCE_LOCK_REJECTED");
});

test("source-lock contract fails closed if request or source/tree guards are removed", () => {
  for (const mutation of [
    SEALED.replace("if ! oidc_response=\"$(", "oidc_response=\"$("),
    SEALED.replace(
      'test "$(git rev-parse HEAD)" = "$AUTHORITY_COMMIT"', "true"
    ),
    SEALED.replace(
      'test "$(git rev-parse HEAD^{tree})" = "$AUTHORITY_TREE"', "true"
    )
  ]) {
    assert.throws(() => assertImmutableSourceLockContract(mutation));
  }
});
