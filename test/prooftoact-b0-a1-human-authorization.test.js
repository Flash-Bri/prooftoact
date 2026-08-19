import assert from "node:assert/strict";
import test from "node:test";

import {
  PROOFTOACT_A1_ACTIONS,
  PROOFTOACT_AUTHORIZATION_ACTION_ENUMS,
  PROOFTOACT_B0_A1_AUTHORIZATION_CONTRACT,
  PROOFTOACT_B0_ACTIONS,
  PROOFTOACT_IMESSAGE_MATERIALIZER,
  buildProofToActB0A1DynamicAuthorizationBinding,
  buildProofToActB0A1HumanAuthorizationReceiptBinding,
  buildProofToActImessageMaterializer,
  renderProofToActB0A1ApprovalReply,
  renderProofToActB0A1HumanAuthorization,
  validateProofToActB0A1DynamicAuthorizationBinding,
  validateProofToActB0A1HumanAuthorizationBytes,
  validateProofToActB0A1HumanAuthorizationReceipt
} from "../scripts/lib/prooftoact-b0-a1-human-authorization.js";
import {
  __test as materializerTest,
  deriveProofToActImessageAuthorityIdentity,
  materializeProofToActB0A1HumanAuthorizationEvidence
} from "../scripts/materialize-prooftoact-b0-a1-human-authorization.js";

const TEST_CONVERSATION = Object.freeze({
  chatGuid: "test-direct-chat-guid",
  chatId: 1,
  chatIdentifier: "authority@test.invalid",
  isGroup: false,
  participant: "authority@test.invalid"
});
const TEST_HMAC_KEY = Buffer.from(
  Array.from({ length: 32 }, (_, index) => index + 1)
);
const TEST_IDENTITY_RECORD = Object.freeze({
  expectedConversation: TEST_CONVERSATION,
  schemaVersion: "prooftoact.private-imessage-authority-identity-record.v1"
});
const TEST_IDENTITY_RECORD_BYTES = Buffer.from(
  `${materializerTest.canonicalJson(TEST_IDENTITY_RECORD)}\n`,
  "utf8"
);

function chatsStdout() {
  return `${JSON.stringify({
    guid: TEST_CONVERSATION.chatGuid,
    id: TEST_CONVERSATION.chatId,
    identifier: TEST_CONVERSATION.chatIdentifier,
    is_group: TEST_CONVERSATION.isGroup,
    participants: [TEST_CONVERSATION.participant]
  })}\n`;
}

function identityReceipt() {
  return deriveProofToActImessageAuthorityIdentity({
    chatsStdout: chatsStdout(),
    hmacKey: TEST_HMAC_KEY,
    identityRecordBytes: TEST_IDENTITY_RECORD_BYTES,
    materializer: PROOFTOACT_IMESSAGE_MATERIALIZER
  });
}

function dynamicBindingInput() {
  const identity = identityReceipt();
  return {
    a1ApprovalId: "223e4567-e89b-42d3-a456-426614174001",
    a1CallerWorkflowRef: "Flash-Bri/prooftoact/.github/workflows/" +
      "prooftoact-fresh-primary.yml@refs/heads/main",
    a1CallerWorkflowSha: "c".repeat(40),
    a1ControllerImportGraphSha256: "d".repeat(64),
    a1CredentialSha256: {
      adoptedAdminPassword: "e".repeat(64),
      auditorTokenValue: "6".repeat(64),
      creatorTokenValue: "7".repeat(64)
    },
    a1ProviderClusterId: "323e4567-e89b-42d3-a456-426614174002",
    a1ProviderReceiptSha256: {
      auditorAuthority: "a".repeat(64),
      creatorAuthority: "b".repeat(64),
      creatorProviderReadback: "c".repeat(64),
      manualCluster: "d".repeat(64),
      pricingSource: "e".repeat(64)
    },
    a1ReservationDeadline: "2026-08-19T09:00:00.000Z",
    a1SqlClusterId: "423e4567-e89b-42d3-a456-426614174003",
    accountId: "123456789012",
    authorizationNotBefore: "2026-08-19T08:00:00.000Z",
    b0DispatchDeadline: "2026-08-19T09:00:00.000Z",
    b0PrivateRecoveryWorkflowCommits: {
      deployment: "f".repeat(40),
      secretSeal: "1".repeat(40)
    },
    b0RuntimeExecutionBindingSha256: "2".repeat(64),
    b0TargetTemplateSha256: {
      freshPrimaryBootstrapRole: "3".repeat(64),
      freshPrimaryCredentialCustody: "4".repeat(64),
      privateRecoveryQueryBootstrap: "5".repeat(64)
    },
    b0WriterValueSha256: {
      auditor: "6".repeat(64),
      cloudApi: "7".repeat(64),
      credential: "8".repeat(64),
      mcp: "9".repeat(64),
      publisher: "a".repeat(64)
    },
    cleanupRetentionDeadline: "2026-08-20T09:00:00.000Z",
    costAuthorization: {
      awsMonthlyResidualCeilingUsdCents: 350,
      cockroachMonthlySubCeilingUsdCents: 200,
      cockroachPaidWorstCaseMonthlyUsdCents: 150,
      combinedMonthlyCeilingUsdCents: 500,
      currency: "USD",
      freeBenefitsAssumed: false,
      maximumOneTimeUsdCents: 500,
      noAdditiveMonthlyCeilings: true,
      reconciliationReceiptSha256: "b".repeat(64)
    },
    humanAuthorizationConversationHmacSha256:
      identity.conversationHmacSha256,
    humanAuthorizationSignerPublicKeySha256:
      identity.signerPublicKeySha256,
    humanAuthoritySenderHmacSha256: identity.senderHmacSha256,
    humanIdentityHmacKeySha256: identity.hmacKeySha256,
    humanIdentityRecordHmacSha256: identity.identityRecordHmacSha256,
    humanIdentityReceiptSha256: identity.identityReceiptSha256,
    operationId: "123e4567-e89b-42d3-a456-426614174000",
    sourceCommit: "a".repeat(40),
    treeDigest: "b".repeat(40)
  };
}

function externalEvidence(intent, overrides = {}) {
  const rendered = renderProofToActB0A1HumanAuthorization(intent);
  const reply = renderProofToActB0A1ApprovalReply(intent);
  const outbound = {
    attachments: [],
    chat_guid: TEST_CONVERSATION.chatGuid,
    chat_id: TEST_CONVERSATION.chatId,
    chat_identifier: TEST_CONVERSATION.chatIdentifier,
    created_at: "2026-08-19T08:00:00.000Z",
    guid: "outbound-guid",
    is_from_me: true,
    is_group: false,
    participants: [TEST_CONVERSATION.participant],
    reply_to_guid: "",
    sender: TEST_CONVERSATION.participant,
    text: rendered.text,
    ...overrides.outbound
  };
  const inbound = {
    attachments: [],
    chat_guid: TEST_CONVERSATION.chatGuid,
    chat_id: TEST_CONVERSATION.chatId,
    chat_identifier: TEST_CONVERSATION.chatIdentifier,
    created_at: "2026-08-19T08:00:01.000Z",
    guid: "inbound-guid",
    is_from_me: false,
    is_group: false,
    participants: [TEST_CONVERSATION.participant],
    reply_to_guid: "outbound-guid",
    sender: TEST_CONVERSATION.participant,
    text: reply.text,
    ...overrides.inbound
  };
  return materializeProofToActB0A1HumanAuthorizationEvidence({
    chatsStdout: chatsStdout(),
    dynamicIntent: intent,
    historyStdout: `${JSON.stringify(inbound)}\n${JSON.stringify(outbound)}\n`,
    hmacKey: TEST_HMAC_KEY,
    identityRecordBytes: TEST_IDENTITY_RECORD_BYTES,
    materializer: buildProofToActImessageMaterializer(intent),
  });
}

test("dynamic intent binds every source, runtime, credential, cost, and deadline coordinate", () => {
  const intent = buildProofToActB0A1DynamicAuthorizationBinding(
    dynamicBindingInput()
  );
  assert.deepEqual(
    validateProofToActB0A1DynamicAuthorizationBinding(intent),
    intent
  );
  assert.equal(Object.hasOwn(intent, "humanAuthorizationReceiptSha256"),
    false);
  assert.equal(intent.cleanupRetentionDeadline,
    "2026-08-20T09:00:00.000Z");
  assert.equal(intent.costAuthorization.combinedMonthlyCeilingUsdCents, 500);
  assert.equal(intent.costAuthorization.cockroachMonthlySubCeilingUsdCents,
    200);
  assert.equal(intent.costAuthorization.awsMonthlyResidualCeilingUsdCents,
    350);
  for (const changed of [
    { ...intent, accountId: "999999999999" },
    { ...intent, sourceCommit: "0".repeat(40) },
    { ...intent, treeDigest: "0".repeat(40) },
    { ...intent, a1CallerWorkflowSha: "f".repeat(40) },
    { ...intent, clusterCreateApproved: true },
    { ...intent, publicClaimAuthorized: true },
    { ...intent, b0DispatchDeadline: "2026-08-19T09:00:00.001Z" },
    { ...intent, cleanupRetentionDeadline: "2026-08-20T08:00:00.000Z" },
    { ...intent, a1SqlClusterId: intent.a1ProviderClusterId },
    {
      ...intent,
      costAuthorization: {
        ...intent.costAuthorization,
        combinedMonthlyCeilingUsdCents: 700
      }
    },
    {
      ...intent,
      b0WriterValueSha256: {
        ...intent.b0WriterValueSha256,
        publisher: "f".repeat(64)
      }
    },
    {
      ...intent,
      a1CredentialSha256: {
        ...intent.a1CredentialSha256,
        creatorTokenValue: "f".repeat(64)
      }
    }
  ]) assert.throws(() =>
    validateProofToActB0A1DynamicAuthorizationBinding(changed),
  /PROOFTOACT_B0_A1_DYNAMIC_AUTHORIZATION_REJECTED/u);
});

test("pre-approval renderer visibly serializes dynamic intent and one combined monthly ceiling", () => {
  const intent = buildProofToActB0A1DynamicAuthorizationBinding(
    dynamicBindingInput()
  );
  const rendered = renderProofToActB0A1HumanAuthorization(intent);
  assert.equal(rendered.bytes.toString("utf8"), `${rendered.text}\n`);
  assert.equal(rendered.bytes.at(-1), 0x0a);
  assert.notEqual(rendered.bytes.at(-2), 0x0a);
  assert.deepEqual(rendered.actionEnums,
    PROOFTOACT_AUTHORIZATION_ACTION_ENUMS);
  for (const value of [
    intent.dynamicIntentSha256,
    intent.accountId,
    intent.operationId,
    intent.sourceCommit,
    intent.treeDigest,
    intent.a1CallerWorkflowSha,
    intent.a1ControllerImportGraphSha256,
    intent.a1ProviderClusterId,
    intent.a1SqlClusterId,
    intent.b0RuntimeExecutionBindingSha256,
    intent.b0WriterValueSha256.credential,
    intent.a1CredentialSha256.adoptedAdminPassword,
    intent.cleanupRetentionDeadline
  ]) assert.match(rendered.text, new RegExp(value));
  assert.match(rendered.text,
    /one combined USD 5\.00 monthly maximum/u);
  assert.match(rendered.text, /These ceilings are not additive/u);
  assert.match(rendered.text, /no third session is authorized/u);
  assert.match(rendered.text,
    /Use iMessage Reply on this exact message, then send exactly:/u);
  assert.match(rendered.replyInstruction,
    new RegExp(rendered.authorizationScopeSha256));
  assert.equal(renderProofToActB0A1ApprovalReply(intent).text,
    `I APPROVE PROOFTOACT B0+A1 ${rendered.authorizationScopeSha256}`);
  assert.equal(PROOFTOACT_B0_A1_AUTHORIZATION_CONTRACT.clusterMode,
    "ADOPT_VERIFIED_EXISTING");
  assert.equal(PROOFTOACT_B0_A1_AUTHORIZATION_CONTRACT
    .clusterCreateApproved, false);
  for (const action of [...PROOFTOACT_B0_ACTIONS,
    ...PROOFTOACT_A1_ACTIONS]) assert.match(rendered.text, new RegExp(action));
  assert.equal(validateProofToActB0A1HumanAuthorizationBytes(
    intent,
    rendered.bytes
  ).sha256, rendered.sha256);
});

test("external evidence finalizes a non-circular receipt over the exact rendered intent", () => {
  const intent = buildProofToActB0A1DynamicAuthorizationBinding(
    dynamicBindingInput()
  );
  const receipt = buildProofToActB0A1HumanAuthorizationReceiptBinding({
    dynamicIntent: intent,
    externalHumanAuthorizationEvidence: externalEvidence(intent)
  });
  assert.deepEqual(validateProofToActB0A1HumanAuthorizationReceipt(receipt),
    receipt);
  assert.deepEqual(validateProofToActB0A1HumanAuthorizationReceipt(
    receipt,
    receipt.dynamicIntent.humanAuthorizationSignerPublicKeySha256
  ), receipt);
  assert.throws(() => validateProofToActB0A1HumanAuthorizationReceipt(
    receipt,
    "0".repeat(64)
  ), /PROOFTOACT_B0_A1_AUTHORIZATION_RECEIPT_REJECTED/u);
  assert.equal(receipt.dynamicIntentSha256, intent.dynamicIntentSha256);
  assert.equal(Object.hasOwn(intent, "receiptBindingSha256"), false);
  for (const changed of [
    { ...receipt, receiptBindingSha256: "f".repeat(64) },
    { ...receipt, humanAuthorizedTextSha256: "f".repeat(64) },
    { ...receipt, externalHumanAuthorizationEvidenceSha256: "f".repeat(64) },
    {
      ...receipt,
      externalHumanAuthorizationEvidence: {
        ...receipt.externalHumanAuthorizationEvidence,
        authorizationSignatureBase64:
          Buffer.alloc(64, 7).toString("base64")
      }
    },
    {
      ...receipt,
      externalHumanAuthorizationEvidence: {
        ...receipt.externalHumanAuthorizationEvidence,
        inboundApprovalEvent: {
          ...receipt.externalHumanAuthorizationEvidence.inboundApprovalEvent,
          receivedAt: "2026-08-19T07:59:59.999Z"
        }
      }
    },
    {
      ...receipt,
      externalHumanAuthorizationEvidence: {
        ...receipt.externalHumanAuthorizationEvidence,
        inboundApprovalEvent: {
          ...receipt.externalHumanAuthorizationEvidence.inboundApprovalEvent,
          receivedAt: "2026-08-19T09:00:00.000Z"
        }
      }
    },
    { ...receipt, clusterCreateApproved: true },
    {
      ...receipt,
      dynamicIntent: { ...receipt.dynamicIntent, sourceCommit: "f".repeat(40) }
    }
  ]) assert.throws(() =>
    validateProofToActB0A1HumanAuthorizationReceipt(changed),
  /PROOFTOACT_B0_A1_AUTHORIZATION_RECEIPT_REJECTED|PROOFTOACT_B0_A1_DYNAMIC_AUTHORIZATION_REJECTED|PROOFTOACT_EXTERNAL_HUMAN_AUTHORIZATION_EVIDENCE_REJECTED/u);
});

test("exact authorization byte validator rejects any edit or newline drift", () => {
  const intent = buildProofToActB0A1DynamicAuthorizationBinding(
    dynamicBindingInput()
  );
  const rendered = renderProofToActB0A1HumanAuthorization(intent);
  for (const bytes of [
    Buffer.from(rendered.text, "utf8"),
    Buffer.from(`${rendered.text}\n\n`, "utf8"),
    Buffer.from(`${rendered.text} \n`, "utf8")
  ]) assert.throws(() =>
    validateProofToActB0A1HumanAuthorizationBytes(intent, bytes),
  /PROOFTOACT_B0_A1_AUTHORIZATION_BYTES_REJECTED/u);
});
