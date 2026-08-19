import assert from "node:assert/strict";
import test from "node:test";

import {
  PROOFTOACT_IMESSAGE_MATERIALIZER,
  buildProofToActB0A1DynamicAuthorizationBinding,
  buildProofToActB0A1HumanAuthorizationReceiptBinding,
  buildProofToActImessageMaterializer,
  renderProofToActB0A1ApprovalReply,
  renderProofToActB0A1HumanAuthorization
} from "../scripts/lib/prooftoact-b0-a1-human-authorization.js";
import {
  __test,
  deriveProofToActImessageAuthorityIdentity,
  materializeProofToActB0A1HumanAuthorizationEvidence,
  parsePinnedImsgHistory,
  verifyProofToActB0A1HumanAuthorizationWithImsg
} from "../scripts/materialize-prooftoact-b0-a1-human-authorization.js";

const CONVERSATION = Object.freeze({
  chatGuid: "private-synthetic-chat-guid",
  chatId: 1,
  chatIdentifier: "reviewed-operator@test.invalid",
  isGroup: false,
  participant: "reviewed-operator@test.invalid"
});
const HMAC_KEY = Buffer.from(
  Array.from({ length: 32 }, (_, index) => 255 - index)
);

function canonicalBytes(value) {
  return Buffer.from(`${__test.canonicalJson(value)}\n`, "utf8");
}

function identityRecord(overrides = {}) {
  return {
    expectedConversation: {
      ...CONVERSATION,
      ...overrides
    },
    schemaVersion: "prooftoact.private-imessage-authority-identity-record.v1"
  };
}

function chatsRecord(overrides = {}) {
  return {
    guid: CONVERSATION.chatGuid,
    id: CONVERSATION.chatId,
    identifier: CONVERSATION.chatIdentifier,
    is_group: CONVERSATION.isGroup,
    participants: [CONVERSATION.participant],
    ...overrides
  };
}

function chatsStdout(overrides = {}) {
  return `${JSON.stringify(chatsRecord(overrides))}\n`;
}

function dynamicInput(identity) {
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

function fixture({ inbound = {}, outbound = {} } = {}) {
  const identityRecordBytes = canonicalBytes(identityRecord());
  const chats = chatsStdout();
  const identity = deriveProofToActImessageAuthorityIdentity({
    chatsStdout: chats,
    hmacKey: HMAC_KEY,
    identityRecordBytes,
    materializer: PROOFTOACT_IMESSAGE_MATERIALIZER
  });
  const dynamicIntent = buildProofToActB0A1DynamicAuthorizationBinding(
    dynamicInput(identity)
  );
  const rendered = renderProofToActB0A1HumanAuthorization(dynamicIntent);
  const reply = renderProofToActB0A1ApprovalReply(dynamicIntent);
  const outboundRecord = {
    attachments: [],
    chat_guid: CONVERSATION.chatGuid,
    chat_id: 1,
    chat_identifier: CONVERSATION.chatIdentifier,
    created_at: "2026-08-19T08:00:00.000Z",
    guid: "outbound-guid",
    is_from_me: true,
    is_group: false,
    participants: [CONVERSATION.participant],
    reply_to_guid: "",
    sender: CONVERSATION.participant,
    text: rendered.text,
    ...outbound
  };
  const inboundRecord = {
    attachments: [],
    chat_guid: CONVERSATION.chatGuid,
    chat_id: 1,
    chat_identifier: CONVERSATION.chatIdentifier,
    created_at: "2026-08-19T08:00:01.000Z",
    guid: "inbound-guid",
    is_from_me: false,
    is_group: false,
    participants: [CONVERSATION.participant],
    reply_to_guid: outboundRecord.guid,
    sender: CONVERSATION.participant,
    text: reply.text,
    ...inbound
  };
  const historyStdout =
    `${JSON.stringify(inboundRecord)}\n${JSON.stringify(outboundRecord)}\n`;
  return {
    chatsStdout: chats,
    dynamicIntent,
    historyStdout,
    hmacKey: HMAC_KEY,
    identityRecordBytes,
    materializer: buildProofToActImessageMaterializer(dynamicIntent)
  };
}

test("private identity record and HMAC key produce no raw identity in public evidence", () => {
  const input = fixture();
  const evidence =
    materializeProofToActB0A1HumanAuthorizationEvidence(input);
  const serialized = JSON.stringify(evidence);
  assert.doesNotMatch(serialized, /reviewed-operator|private-synthetic/u);
  assert.doesNotMatch(serialized, /hmacKeyBase64|expectedConversation/u);
  assert.equal(evidence.authorityId, "REVIEWED_DIRECT_HUMAN_OPERATOR");
  assert.equal(evidence.materializer.history.start,
    input.dynamicIntent.authorizationNotBefore);
  assert.equal(evidence.materializer.history.end,
    input.dynamicIntent.b0DispatchDeadline);
  assert.equal(evidence.materializer.history.limit, 10000);
});

test("identity derivation rejects every expected-conversation field mismatch", () => {
  for (const changed of [
    { chatGuid: "wrong-guid" },
    { chatId: 2 },
    { chatIdentifier: "wrong@test.invalid" },
    { isGroup: true },
    { participant: "wrong@test.invalid" }
  ]) assert.throws(() => deriveProofToActImessageAuthorityIdentity({
    chatsStdout: chatsStdout(),
    hmacKey: HMAC_KEY,
    identityRecordBytes: canonicalBytes(identityRecord(changed)),
    materializer: PROOFTOACT_IMESSAGE_MATERIALIZER
  }), /PROOFTOACT_IMESSAGE_AUTHORIZATION_/u);
});

test("event materialization rejects key, identity, body, thread, time, and cardinality drift", () => {
  const rotatedKey = Buffer.from(HMAC_KEY);
  rotatedKey[0] ^= 0xff;
  const cases = [
    { transform: (value) => ({ ...value, hmacKey: rotatedKey }) },
    {
      transform: (value) => ({
        ...value,
        identityRecordBytes: canonicalBytes(identityRecord({
          chatGuid: "different-guid"
        }))
      })
    },
    { inbound: { text: "edited reply" } },
    { inbound: { reply_to_guid: "" } },
    { inbound: { sender: "wrong@test.invalid" } },
    { inbound: { chat_guid: "wrong-chat" } },
    { inbound: { created_at: "2026-08-19T07:59:59.999Z" } },
    { inbound: { created_at: "2026-08-19T09:00:00.000Z" } },
    { inbound: { attachments: [{ id: "attachment" }] } },
    { outbound: { text: "edited proposal" } },
    { outbound: { created_at: "2026-08-19T07:59:59.999Z" } },
    { outbound: { created_at: "2026-08-19T09:00:00.000Z" } },
    { outbound: { attachments: [{ id: "attachment" }] } }
  ];
  for (const item of cases) {
    const base = fixture(item);
    const changed = item.transform ? item.transform(base) : base;
    assert.throws(() =>
      materializeProofToActB0A1HumanAuthorizationEvidence(changed),
    /PROOFTOACT_IMESSAGE_AUTHORIZATION_/u);
  }
  for (const duplicate of ["inbound", "outbound"]) {
    const base = fixture();
    const lines = base.historyStdout.trimEnd().split("\n");
    const extra = duplicate === "inbound" ? lines[0] : lines[1];
    assert.throws(() =>
      materializeProofToActB0A1HumanAuthorizationEvidence({
        ...base,
        historyStdout: `${base.historyStdout}${extra}\n`
      }), /PROOFTOACT_IMESSAGE_AUTHORIZATION_EVENTS_REJECTED/u);
  }
});

test("history parser rejects malformed JSON and records beyond its hard cap", () => {
  assert.throws(() => parsePinnedImsgHistory("{not-json}\n"),
    /PROOFTOACT_IMESSAGE_AUTHORIZATION_HISTORY_REJECTED/u);
  const base = JSON.parse(fixture().historyStdout.trimEnd().split("\n")[0]);
  const oversized = `${Array.from({ length: 10001 }, (_, index) =>
    JSON.stringify({ ...base, guid: `nonmatch-${index}`, text: null })
  ).join("\n")}\n`;
  assert.throws(() => parsePinnedImsgHistory(oversized),
    /PROOFTOACT_IMESSAGE_AUTHORIZATION_HISTORY_REJECTED/u);
});

test("live verifier re-materializes the exact two events and rejects readback drift", async () => {
  const input = fixture();
  const evidence =
    materializeProofToActB0A1HumanAuthorizationEvidence(input);
  const receipt = buildProofToActB0A1HumanAuthorizationReceiptBinding({
    dynamicIntent: input.dynamicIntent,
    externalHumanAuthorizationEvidence: evidence
  });
  const executeHistory = async () => ({
    chatsStdout: input.chatsStdout,
    historyStdout: input.historyStdout,
    materializer: input.materializer
  });
  assert.deepEqual(await verifyProofToActB0A1HumanAuthorizationWithImsg(
    receipt,
    input.identityRecordBytes,
    input.hmacKey,
    { executeHistory }
  ), receipt);
  await assert.rejects(() =>
    verifyProofToActB0A1HumanAuthorizationWithImsg(
      receipt,
      input.identityRecordBytes,
      input.hmacKey,
      {
        executeHistory: async () => ({
          chatsStdout: input.chatsStdout,
          historyStdout: input.historyStdout.replace(
            "inbound-guid",
            "changed-inbound-guid"
          ),
          materializer: input.materializer
        })
      }
    ), /PROOFTOACT_IMESSAGE_AUTHORIZATION_LIVE_READBACK_REJECTED/u);
});

test("materializer command contract is exact and drift changes its digest", () => {
  const input = fixture();
  const materializer = buildProofToActImessageMaterializer(
    input.dynamicIntent
  );
  assert.equal(materializer.tool.executablePath, "/opt/homebrew/bin/imsg");
  assert.equal(materializer.tool.historyChatId, 1);
  assert.match(materializer.tool.executableSha256, /^[0-9a-f]{64}$/u);
  assert.match(materializer.history.invocationSha256, /^[0-9a-f]{64}$/u);
  assert.notEqual(materializer.history.invocationSha256,
    buildProofToActImessageMaterializer({
      ...input.dynamicIntent,
      authorizationNotBefore: "2026-08-19T08:00:00.001Z"
    }).history.invocationSha256);
  assert.deepEqual(__test.CHATS_ARGUMENTS,
    ["chats", "--limit", "200", "--json"]);
});
