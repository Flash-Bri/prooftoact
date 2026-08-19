import assert from "node:assert/strict";
import test from "node:test";

import {
  PROOFTOACT_A1_ACTIONS,
  PROOFTOACT_AUTHORIZATION_ACTION_ENUMS,
  PROOFTOACT_B0_A1_AUTHORIZATION_CONTRACT,
  PROOFTOACT_B0_A1_HUMAN_AUTHORIZATION_TEXT_SHA256,
  PROOFTOACT_B0_ACTIONS,
  buildProofToActB0A1HumanAuthorizationReceiptBinding,
  renderProofToActB0A1HumanAuthorization,
  validateProofToActB0A1HumanAuthorizationBytes,
  validateProofToActB0A1HumanAuthorizationReceipt
} from "../scripts/lib/prooftoact-b0-a1-human-authorization.js";

test("shared B0+A1 authorization renders one exact newline and enumerates both boundaries", () => {
  const rendered = renderProofToActB0A1HumanAuthorization();
  assert.equal(rendered.bytes.toString("utf8"), `${rendered.text}\n`);
  assert.equal(rendered.bytes.at(-1), 0x0a);
  assert.notEqual(rendered.bytes.at(-2), 0x0a);
  assert.equal(rendered.sha256,
    PROOFTOACT_B0_A1_HUMAN_AUTHORIZATION_TEXT_SHA256);
  assert.deepEqual(rendered.actionEnums,
    PROOFTOACT_AUTHORIZATION_ACTION_ENUMS);
  assert.match(rendered.text, /latest-new-dispatch boundary/u);
  assert.match(rendered.text,
    /latest-durable-outer-reservation boundary/u);
  assert.match(rendered.text, /fixed 45-minute workflow timeout/u);
  assert.equal(PROOFTOACT_B0_A1_AUTHORIZATION_CONTRACT.clusterMode,
    "ADOPT_VERIFIED_EXISTING");
  assert.equal(PROOFTOACT_B0_A1_AUTHORIZATION_CONTRACT
    .clusterCreateApproved, false);
  assert.equal(PROOFTOACT_B0_A1_AUTHORIZATION_CONTRACT
    .futureCockroachRevokerAuthorized, false);
  assert.equal(PROOFTOACT_B0_A1_AUTHORIZATION_CONTRACT
    .publicClaimAuthorized, false);
  for (const action of [...PROOFTOACT_B0_ACTIONS,
    ...PROOFTOACT_A1_ACTIONS]) assert.match(rendered.text, new RegExp(action));
  assert.equal(validateProofToActB0A1HumanAuthorizationBytes(
    rendered.bytes
  ).sha256, rendered.sha256);
});

test("shared authorization byte validator rejects any edit or newline drift", () => {
  const rendered = renderProofToActB0A1HumanAuthorization();
  for (const bytes of [
    Buffer.from(rendered.text, "utf8"),
    Buffer.from(`${rendered.text}\n\n`, "utf8"),
    Buffer.from(`${rendered.text} \n`, "utf8")
  ]) assert.throws(() =>
    validateProofToActB0A1HumanAuthorizationBytes(bytes),
  /PROOFTOACT_B0_A1_AUTHORIZATION_BYTES_REJECTED/u);
});

test("shared receipt validator requires exact action equality and fail-closed flags", () => {
  const receipt = buildProofToActB0A1HumanAuthorizationReceiptBinding();
  assert.deepEqual(validateProofToActB0A1HumanAuthorizationReceipt(receipt),
    receipt);
  for (const changed of [
    { ...receipt, clusterCreateApproved: true },
    { ...receipt, futureCockroachRevokerAuthorized: true },
    { ...receipt, publicClaimAuthorized: true },
    { ...receipt, humanAuthorizedTextSha256: "f".repeat(64) },
    {
      ...receipt,
      actionEnums: {
        ...receipt.actionEnums,
        a1: receipt.actionEnums.a1.slice(1)
      }
    }
  ]) assert.throws(() =>
    validateProofToActB0A1HumanAuthorizationReceipt(changed),
  /PROOFTOACT_B0_A1_AUTHORIZATION_RECEIPT_REJECTED/u);
});
