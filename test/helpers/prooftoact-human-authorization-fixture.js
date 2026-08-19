import {
  PROOFTOACT_IMESSAGE_MATERIALIZER,
  buildProofToActB0A1DynamicAuthorizationBinding,
  buildProofToActB0A1HumanAuthorizationReceiptBinding,
  buildProofToActImessageMaterializer,
  renderProofToActB0A1ApprovalReply,
  renderProofToActB0A1HumanAuthorization
} from "../../scripts/lib/prooftoact-b0-a1-human-authorization.js";
import {
  __test as materializerTest,
  deriveProofToActImessageAuthorityIdentity,
  materializeProofToActB0A1HumanAuthorizationEvidence
} from "../../scripts/materialize-prooftoact-b0-a1-human-authorization.js";

const CONVERSATION = Object.freeze({
  chatGuid: "synthetic-direct-chat-guid",
  chatId: 1,
  chatIdentifier: "authority@test.invalid",
  isGroup: false,
  participant: "authority@test.invalid"
});
const HMAC_KEY = Buffer.from(
  Array.from({ length: 32 }, (_, index) => index + 1)
);
const IDENTITY_RECORD = Object.freeze({
  expectedConversation: CONVERSATION,
  schemaVersion: "prooftoact.private-imessage-authority-identity-record.v1"
});
const IDENTITY_RECORD_BYTES = Buffer.from(
  `${materializerTest.canonicalJson(IDENTITY_RECORD)}\n`,
  "utf8"
);

function chatsStdout() {
  return `${JSON.stringify({
    guid: CONVERSATION.chatGuid,
    id: CONVERSATION.chatId,
    identifier: CONVERSATION.chatIdentifier,
    is_group: CONVERSATION.isGroup,
    participants: [CONVERSATION.participant]
  })}\n`;
}

function identityReceipt() {
  return deriveProofToActImessageAuthorityIdentity({
    chatsStdout: chatsStdout(),
    hmacKey: HMAC_KEY,
    identityRecordBytes: IDENTITY_RECORD_BYTES,
    materializer: PROOFTOACT_IMESSAGE_MATERIALIZER
  });
}

export function buildSyntheticProofToActHumanAuthorization({
  dynamicInput,
  inboundAt,
  outboundAt
}) {
  const identity = identityReceipt();
  const dynamicIntent = buildProofToActB0A1DynamicAuthorizationBinding({
    ...dynamicInput,
    humanAuthorizationConversationHmacSha256:
      identity.conversationHmacSha256,
    humanAuthorizationSignerPublicKeySha256:
      identity.signerPublicKeySha256,
    humanAuthoritySenderHmacSha256: identity.senderHmacSha256,
    humanIdentityHmacKeySha256: identity.hmacKeySha256,
    humanIdentityRecordHmacSha256: identity.identityRecordHmacSha256,
    humanIdentityReceiptSha256: identity.identityReceiptSha256
  });
  const rendered = renderProofToActB0A1HumanAuthorization(dynamicIntent);
  const reply = renderProofToActB0A1ApprovalReply(dynamicIntent);
  const outbound = {
    attachments: [],
    chat_guid: CONVERSATION.chatGuid,
    chat_id: CONVERSATION.chatId,
    chat_identifier: CONVERSATION.chatIdentifier,
    created_at: outboundAt,
    guid: "synthetic-outbound-guid",
    is_from_me: true,
    is_group: false,
    participants: [CONVERSATION.participant],
    reply_to_guid: "",
    sender: CONVERSATION.participant,
    text: rendered.text
  };
  const inbound = {
    attachments: [],
    chat_guid: CONVERSATION.chatGuid,
    chat_id: CONVERSATION.chatId,
    chat_identifier: CONVERSATION.chatIdentifier,
    created_at: inboundAt,
    guid: "synthetic-inbound-guid",
    is_from_me: false,
    is_group: false,
    participants: [CONVERSATION.participant],
    reply_to_guid: outbound.guid,
    sender: CONVERSATION.participant,
    text: reply.text
  };
  const externalHumanAuthorizationEvidence =
    materializeProofToActB0A1HumanAuthorizationEvidence({
      chatsStdout: chatsStdout(),
      dynamicIntent,
      historyStdout:
        `${JSON.stringify(inbound)}\n${JSON.stringify(outbound)}\n`,
      hmacKey: HMAC_KEY,
      identityRecordBytes: IDENTITY_RECORD_BYTES,
      materializer: buildProofToActImessageMaterializer(dynamicIntent)
    });
  const humanAuthorizationBinding =
    buildProofToActB0A1HumanAuthorizationReceiptBinding({
      dynamicIntent,
      externalHumanAuthorizationEvidence
    });
  return Object.freeze({ dynamicIntent, humanAuthorizationBinding });
}

export const syntheticHumanAuthorizationFixture = Object.freeze({
  chatsStdout,
  conversation: CONVERSATION,
  hmacKey: HMAC_KEY,
  identityRecordBytes: IDENTITY_RECORD_BYTES,
  identityReceipt
});
