import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync
} from "node:crypto";
import test from "node:test";

import {
  createCommittedRecoveryPublisherSigner,
  loadCommittedRecoveryPublisherSigner
} from "../scripts/lib/recovery-publisher-key.js";
import {
  resolveCommittedRecoveryPublisherTrustRoot,
  trustedPublisherKeysDigest
} from "../src/cloud/recovery-broker.js";

const TRUST_ROOT_SCHEMA = "tideproof.recovery-publisher-trust-root.v1";
const COMMITMENT_DOMAIN =
  "tideproof-recovery-publisher-trust-root-commitment-v1\n";

function fixture() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256"
  });
  const publisherKeyId = "gate1-recovery-publisher-p256-v1";
  const publicKeySpkiBase64 = publicKey
    .export({ type: "spki", format: "der" })
    .toString("base64");
  const trustRootJson = JSON.stringify({
    schemaVersion: TRUST_ROOT_SCHEMA,
    publisherKeyId,
    publicKeySpkiBase64
  });
  const trustRootCommitment = createHash("sha256")
    .update(`${COMMITMENT_DOMAIN}${trustRootJson}`)
    .digest("hex");
  const privateKeyPkcs8Base64 = privateKey
    .export({ type: "pkcs8", format: "der" })
    .toString("base64");
  return {
    publisherKeyId,
    publicKeySpkiBase64,
    trustRootJson,
    trustRootCommitment,
    privateKeyPkcs8Base64
  };
}

test("recovery publisher requires an independently committed matching trust root", () => {
  const input = fixture();
  const signer = createCommittedRecoveryPublisherSigner(input);

  assert.equal(signer.publisherKeyId, input.publisherKeyId);
  assert.equal(signer.publicKeySpkiBase64, input.publicKeySpkiBase64);
  assert.equal(signer.trustRootCommitment, input.trustRootCommitment);
  assert.deepEqual(signer.trustedPublisherKeys, {
    [input.publisherKeyId]: input.publicKeySpkiBase64
  });
});

test("recovery publisher rejects a changed root after commitment", () => {
  const input = fixture();
  const changed = JSON.parse(input.trustRootJson);
  changed.publisherKeyId = "changed-recovery-publisher-p256-v1";

  assert.throws(
    () =>
      createCommittedRecoveryPublisherSigner({
        ...input,
        trustRootJson: JSON.stringify(changed)
      }),
    /RECOVERY_PUBLISHER_TRUST_ROOT_COMMITMENT_MISMATCH/
  );
});

test("recovery publisher rejects a signing key outside the committed root", () => {
  const input = fixture();
  const replacement = fixture();

  assert.throws(
    () =>
      createCommittedRecoveryPublisherSigner({
        ...input,
        privateKeyPkcs8Base64: replacement.privateKeyPkcs8Base64
      }),
    /RECOVERY_PUBLISHER_SIGNING_KEY_MISMATCH/
  );
});

test("recovery publisher environment loader keeps commitment and key separate", () => {
  const input = fixture();
  const signer = loadCommittedRecoveryPublisherSigner({
    TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT: input.trustRootJson,
    TIDEPROOF_RECOVERY_PUBLISHER_TRUST_ROOT_COMMITMENT:
      input.trustRootCommitment,
    RECOVERY_PUBLISHER_PRIVATE_KEY_PKCS8_BASE64:
      input.privateKeyPkcs8Base64
  });

  assert.equal(signer.trustRootCommitment, input.trustRootCommitment);
  assert.throws(
    () => loadCommittedRecoveryPublisherSigner({}),
    /RECOVERY_PUBLISHER_TRUST_ROOT_REQUIRED/
  );
});

test("recovery publisher rejects noncanonical PKCS8 base64 padding", () => {
  const input = fixture();
  assert.throws(
    () =>
      createCommittedRecoveryPublisherSigner({
        ...input,
        privateKeyPkcs8Base64: `${input.privateKeyPkcs8Base64}====`
      }),
    /RECOVERY_PUBLISHER_PRIVATE_KEY_REQUIRED/
  );
});

test("primary-ledger commitment rejects coordinated root commitment and key replacement", async () => {
  const committedSigner = createCommittedRecoveryPublisherSigner(fixture());
  const replacementSigner = createCommittedRecoveryPublisherSigner(fixture());
  const committedKeySetDigest = trustedPublisherKeysDigest(
    committedSigner.trustedPublisherKeys
  );
  const clientFactory = () => ({
    async connect() {},
    async end() {},
    async query(_text, values) {
      const matches =
        values[1] === committedSigner.trustRootCommitment &&
        values[2] === committedKeySetDigest;
      return matches
        ? {
            rowCount: 1,
            rows: [{
              trust_root_id: "gate1-recovery-publisher-v1",
              trust_root_commitment: committedSigner.trustRootCommitment,
              publisher_key_set_digest: committedKeySetDigest,
              committed_at: new Date("2026-08-03T05:00:00.000Z"),
              database_now: new Date("2026-08-03T05:01:00.000Z")
            }]
          }
        : { rowCount: 0, rows: [] };
    }
  });

  const committed = await resolveCommittedRecoveryPublisherTrustRoot({
    trustRootCommitment: committedSigner.trustRootCommitment,
    publisherKeySetDigest: committedKeySetDigest,
    clientFactory
  });
  assert.equal(committed.trustRootCommitment, committedSigner.trustRootCommitment);

  await assert.rejects(
    resolveCommittedRecoveryPublisherTrustRoot({
      trustRootCommitment: replacementSigner.trustRootCommitment,
      publisherKeySetDigest: trustedPublisherKeysDigest(
        replacementSigner.trustedPublisherKeys
      ),
      clientFactory
    }),
    /RECOVERY_PUBLISHER_TRUST_ROOT_NOT_COMMITTED/
  );
});
