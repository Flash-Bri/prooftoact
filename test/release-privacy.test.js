import assert from "node:assert/strict";
import test from "node:test";

import {
  __test,
  forbiddenTrackedPath,
  reviewFindings,
  safeFailureCode,
  scanBuffer,
  validateManifest
} from "../scripts/verify-release-privacy.js";

const HEX_A = "a".repeat(64);
const HEX_B = "b".repeat(64);

function fragments(...parts) {
  return parts.join("");
}

function fixtureManifest(overrides = {}) {
  return {
    schema: "tideproof.release-privacy-manifest.v1",
    status: "CURRENT_PUBLIC_HISTORY_REVIEWED_FINAL_RELEASE_PENDING",
    reviewedOn: "2026-07-31",
    allowedFindings: [
      {
        rule: "email-address",
        path: "fixture.txt",
        matchSha256: HEX_A,
        classification: "SYNTHETIC_TEST_FIXTURE"
      }
    ],
    allowedCommitIdentityDigests: [HEX_B],
    syntheticAwsAccountIds: ["111111111111"],
    finalReleaseReady: false,
    ...overrides
  };
}

test("scanner recognizes each bounded high-confidence signature", () => {
  const values = [
    ["pem-private-key", fragments("-----BEGIN ", "PRIVATE KEY-----")],
    ["aws-access-key", fragments("AK", "IA", "ABCDEFGHIJKLMNOP")],
    ["github-token", fragments("gh", "p_", "A".repeat(24))],
    ["model-provider-key", fragments("sk", "-proj-", "A".repeat(24))],
    ["slack-token", fragments("xox", "b-", "A".repeat(24))],
    ["google-api-key", fragments("AI", "za", "A".repeat(35))],
    ["stripe-secret", fragments("sk", "_live_", "A".repeat(24))],
    [
      "jwt",
      fragments(
        "eyJ",
        "A".repeat(12),
        ".eyJ",
        "B".repeat(12),
        ".",
        "C".repeat(12)
      )
    ],
    [
      "basic-auth-url",
      fragments(
        "postgresql://user:",
        "password",
        "@db.example.invalid/app"
      )
    ],
    ["bearer-token", fragments("Bearer ", "A".repeat(24))],
    ["private-home-path", fragments("/Us", "ers/person/project/")],
    ["private-ipv4", fragments("192", ".168.10.20")],
    ["email-address", fragments("person", "@example.invalid")],
    [
      "aws-account-id",
      fragments("arn:", "aws:iam::123456789012:role/fixture")
    ]
  ];
  const source = values.map(([, value]) => value).join("\n");
  const findings = scanBuffer(Buffer.from(source), "fixture.txt");
  assert.deepEqual(
    new Set(findings.map((finding) => finding.rule)),
    new Set(values.map(([rule]) => rule))
  );
});

test("scanner returns no raw matched value in a public receipt shape", () => {
  const value = fragments("person", "@example.invalid");
  const [finding] = scanBuffer(Buffer.from(value), "fixture.txt");
  assert.equal(finding.matchSha256, __test.sha256(value));
  assert.equal(finding.path, "fixture.txt");
});

test("manifest validation requires canonical sorted bounded allowances", () => {
  assert.equal(validateManifest(fixtureManifest()).finalReleaseReady, false);
  assert.throws(
    () =>
      validateManifest(
        fixtureManifest({
          status: "FINAL_RELEASE_READY"
        })
      ),
    /RELEASE_PRIVACY_MANIFEST_BOUNDARY/
  );
  assert.throws(
    () =>
      validateManifest(
        fixtureManifest({
          allowedCommitIdentityDigests: [HEX_B, HEX_B]
        })
      ),
    /RELEASE_PRIVACY_MANIFEST_IDENTITIES/
  );
});

test("finding review accepts only exact hash and path allowances", () => {
  const manifest = fixtureManifest();
  const accepted = reviewFindings(
    [
      {
        rule: "email-address",
        path: "fixture.txt",
        matchSha256: HEX_A,
        matchedValue: fragments("person", "@example.invalid")
      }
    ],
    manifest
  );
  assert.equal(accepted.findingCount, 1);
  assert.throws(
    () =>
      reviewFindings(
        [
          {
            rule: "email-address",
            path: "other.txt",
            matchSha256: HEX_A,
            matchedValue: fragments("person", "@example.invalid")
          }
        ],
        manifest
      ),
    /RELEASE_PRIVACY_UNREVIEWED_FINDING/
  );
});

test("finding review accepts only named synthetic AWS fixtures in tests", () => {
  const manifest = fixtureManifest({ allowedFindings: [] });
  assert.equal(
    reviewFindings(
      [
        {
          rule: "aws-account-id",
          path: "test/fixture.test.js",
          matchSha256: HEX_A,
          matchedValue: "111111111111"
        }
      ],
      manifest
    ).findingCount,
    1
  );
  assert.throws(
    () =>
      reviewFindings(
        [
          {
            rule: "aws-account-id",
            path: "src/runtime.js",
            matchSha256: HEX_A,
            matchedValue: "111111111111"
          }
        ],
        manifest
      ),
    /RELEASE_PRIVACY_UNREVIEWED_FINDING/
  );
});

test("tracked path policy rejects common credential containers", () => {
  assert.equal(forbiddenTrackedPath(".env"), true);
  assert.equal(forbiddenTrackedPath("config/.env.production"), true);
  assert.equal(forbiddenTrackedPath("identity/private.pem"), true);
  assert.equal(forbiddenTrackedPath("operator/.aws/credentials"), true);
  assert.equal(forbiddenTrackedPath(".env.example"), false);
  assert.equal(forbiddenTrackedPath("SECURITY.md"), false);
});

test("batch parser rejects truncated or mismatched Git blob output", () => {
  const body = Buffer.from("fixture\n");
  const oid = "1".repeat(40);
  const valid = Buffer.concat([
    Buffer.from(`${oid} blob ${body.length}\n`),
    body,
    Buffer.from("\n")
  ]);
  assert.equal(
    __test.parseBatch(valid, [
      { oid, path: "fixture.txt", size: body.length }
    ])[0].body.toString("utf8"),
    "fixture\n"
  );
  assert.throws(
    () =>
      __test.parseBatch(valid.subarray(0, -1), [
        { oid, path: "fixture.txt", size: body.length }
      ]),
    /RELEASE_PRIVACY_BATCH_BODY/
  );
});

test("privacy CLI preserves a safe base code without leaking finding detail", () => {
  assert.equal(
    safeFailureCode(
      new Error(
        "RELEASE_PRIVACY_UNREVIEWED_FINDING:basic-auth-url:test/fixture.js:deadbeef"
      )
    ),
    "RELEASE_PRIVACY_UNREVIEWED_FINDING"
  );
  assert.equal(
    safeFailureCode(new Error("/private/path:credential-like-value")),
    "RELEASE_PRIVACY_UNKNOWN"
  );
});
