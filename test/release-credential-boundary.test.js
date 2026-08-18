import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  buildReleaseCredentialSeal
} from "../scripts/build-release-credential-seal.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const BOOTSTRAP_COMMIT = "50d0cd261b8597fe74c80b84c49be0adde5bdf6f";
const BOOTSTRAP_TREE = "237ffafec3232a017c2bcf95f94609026447616d";
const HEX_64 = /^[0-9a-f]{64}$/u;

function temporaryPath(name) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "pta-seal-test-"));
  return Object.freeze({ parent, root: path.join(parent, name) });
}

test("seal generator publishes exact create-only non-executable bytes", () => {
  const temporary = temporaryPath("seal");
  try {
    const receipt = buildReleaseCredentialSeal({
      authorityCommit: BOOTSTRAP_COMMIT,
      authorityTree: BOOTSTRAP_TREE,
      environment: "aws-release-deployment",
      lane: "prepare",
      outputRoot: temporary.root,
      phase: "dispatch"
    });
    assert.match(receipt.commandSha256, HEX_64);
    assert.match(receipt.manifestSha256, HEX_64);
    assert.equal(Buffer.from(receipt.commandBase64, "base64").equals(
      fs.readFileSync(path.join(temporary.root, "command.json"))), true);
    assert.equal(Buffer.from(receipt.manifestBase64, "base64").equals(
      fs.readFileSync(path.join(temporary.root, "manifest.json"))), true);
    assert.equal(receipt.status, "SEALED_NON_EXECUTABLE_COMMAND_GENERATED");
    assert.deepEqual(fs.readdirSync(temporary.root), [
      "command.json", "manifest.json"
    ]);
    for (const name of fs.readdirSync(temporary.root)) {
      const stat = fs.lstatSync(path.join(temporary.root, name));
      assert.equal(stat.isFile(), true);
      assert.equal(stat.isSymbolicLink(), false);
      assert.equal(stat.nlink, 1);
      assert.equal(stat.mode & 0o777, 0o600);
    }
    const command = JSON.parse(fs.readFileSync(
      path.join(temporary.root, "command.json"), "utf8"));
    assert.equal(command.action, "HOLD_NO_PROVIDER_EXECUTION");
    assert.equal(Object.hasOwn(command, "command"), false);
    assert.equal(Object.hasOwn(command, "arguments"), false);
    assert.equal(Object.hasOwn(command, "roleArn"), false);
  } finally {
    fs.rmSync(temporary.parent, { recursive: true, force: true });
  }
});

test("wrong lane, environment, phase, identity, and occupied roots reject", () => {
  for (const drift of [
    { lane: "execute" },
    { environment: "aws-release-execution" },
    { phase: "execute" },
    { authorityCommit: "f".repeat(39) },
    { authorityTree: BOOTSTRAP_COMMIT }
  ]) {
    const temporary = temporaryPath("seal");
    try {
      assert.throws(() => buildReleaseCredentialSeal({
        authorityCommit: BOOTSTRAP_COMMIT,
        authorityTree: BOOTSTRAP_TREE,
        environment: "aws-release-deployment",
        lane: "prepare",
        outputRoot: temporary.root,
        phase: "dispatch",
        ...drift
      }), /RELEASE_CREDENTIAL_SEAL_INPUT_REJECTED/u);
    } finally {
      fs.rmSync(temporary.parent, { recursive: true, force: true });
    }
  }
  const temporary = temporaryPath("seal");
  try {
    fs.mkdirSync(temporary.root, { mode: 0o700 });
    fs.writeFileSync(path.join(temporary.root, "occupied"), "x", {
      mode: 0o600
    });
    assert.throws(() => buildReleaseCredentialSeal({
      authorityCommit: BOOTSTRAP_COMMIT,
      authorityTree: BOOTSTRAP_TREE,
      environment: "aws-release-deployment",
      lane: "prepare",
      outputRoot: temporary.root,
      phase: "dispatch"
    }), /RELEASE_CREDENTIAL_SEAL_OUTPUT_REJECTED/u);
  } finally {
    fs.rmSync(temporary.parent, { recursive: true, force: true });
  }
});

test("all token-capable reusable workflows are immutable, minimal, and held", () => {
  const workflows = {
    "prooftoact-sealed-coordinator.yml": {
      environment: "aws-release-coordination",
      phases: ["reserve", "finalize"]
    },
    "prooftoact-sealed-prepare.yml": {
      environment: "aws-release-deployment",
      phases: ["dispatch"]
    }
  };
  for (const [file, contract] of Object.entries(workflows)) {
    const source = fs.readFileSync(path.join(ROOT, ".github/workflows", file),
      "utf8");
    assert.match(source, /^  workflow_call:$/mu);
    assert.match(source, new RegExp(
      `^    environment: ${contract.environment}$`, "mu"));
    assert.equal((source.match(/id-token: write/gu) ?? []).length, 1);
    assert.equal((source.match(/^\s+uses:/gmu) ?? []).length, 0);
    assert.doesNotMatch(source, /actions:\s*read/u);
    assert.doesNotMatch(source,
      /actions\/checkout|actions\/setup-node|npm\s|npm:|configure-aws-credentials|\baws\s/u);
    assert.doesNotMatch(source, /\brun:\s*(?:node|python|bash|sh)\b/u);
    assert.match(source, /HOLD:[A-Z0-9_]+/u);
    assert.match(source, /sha256sum/u);
    assert.match(source, /base64 --decode/u);
    assert.match(source, /HASH_BOUND_NOT_EXECUTABLE/u);
    for (const phase of contract.phases) assert.match(source,
      new RegExp(phase, "u"));
  }

  for (const file of [
    "prooftoact-sealed-execute.yml",
    "prooftoact-sealed-live-drill.yml",
    "prooftoact-sealed-evidence.yml",
    "prooftoact-sealed-teardown.yml",
    "prooftoact-sealed-terminalizer.yml"
  ]) {
    const source = fs.readFileSync(path.join(ROOT, ".github/workflows", file),
      "utf8");
    assert.doesNotMatch(source, /id-token: write|configure-aws-credentials/u);
    assert.match(source, /HOLD:[A-Z0-9_]+/u);
  }
});

test("all seven role trusts bind the exact bootstrap reusable bytes", async () => {
  const template = JSON.parse(fs.readFileSync(path.join(ROOT,
    "infra/aws/release-deployment-roles-template.json"), "utf8"));
  const expected = {
    LiveDrillOperatorRole: "prooftoact-sealed-live-drill.yml",
    ReleaseCoordinatorRole: "prooftoact-sealed-coordinator.yml",
    ReleaseDeploymentRole: "prooftoact-sealed-prepare.yml",
    ReleaseEvidenceRole: "prooftoact-sealed-evidence.yml",
    ReleaseExecutionRole: "prooftoact-sealed-execute.yml",
    ReleaseTeardownRole: "prooftoact-sealed-teardown.yml",
    ReleaseTerminalizerRole: "prooftoact-sealed-terminalizer.yml"
  };
  for (const [logicalId, workflow] of Object.entries(expected)) {
    const equals = template.Resources[logicalId].Properties
      .AssumeRolePolicyDocument.Statement[0].Condition.StringEquals;
    assert.equal(equals["token.actions.githubusercontent.com:job_workflow_ref"],
      `Flash-Bri/prooftoact/.github/workflows/${workflow}@${BOOTSTRAP_COMMIT}`);
    const drift = structuredClone(template);
    drift.Resources[logicalId].Properties.AssumeRolePolicyDocument.Statement[0]
      .Condition.StringEquals[
        "token.actions.githubusercontent.com:job_workflow_ref"
      ] = `Flash-Bri/prooftoact/.github/workflows/${workflow}@refs/heads/main`;
    const { validateReleaseDeploymentRoleTemplate } = await import(
      "../scripts/prepare-release-deployment.js");
    const gate2 = JSON.parse(fs.readFileSync(path.join(ROOT,
      "infra/aws/gate2-template.json"), "utf8"));
    assert.throws(() => validateReleaseDeploymentRoleTemplate(drift, gate2),
      /RELEASE_PLAN_OIDC_TRUST_REJECTED/u);
  }
});
