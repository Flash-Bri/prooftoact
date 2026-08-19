import assert from "node:assert/strict";
import test from "node:test";

import { packageNamesFromMetafile } from "../scripts/lib/bundled-third-party-notices.js";
import { verifyCurrentBundledThirdPartyNotices } from "../scripts/verify-bundled-third-party-notices.js";

test("current Gate Two bundle union has exact verified license notices", async () => {
  const receipt = await verifyCurrentBundledThirdPartyNotices();

  assert.equal(receipt.status, "PASS");
  assert.equal(receipt.noticePath, "THIRD_PARTY_NOTICES.txt");
  assert.match(receipt.noticeSha256, /^[a-f0-9]{64}$/);
  assert.equal(receipt.packageCount, 52);
  assert.equal(receipt.packageNames.length, 52);
  assert(receipt.packageNames.includes("pg"));
  assert.equal(receipt.licenseTextCount, 20);
  assert.equal(receipt.fallbackCount, 5);
  assert.deepEqual(receipt.licenses, {
    "Apache-2.0": 35,
    ISC: 2,
    MIT: 15
  });
  assert.deepEqual(receipt.artifactPackages.demo, []);
  assert(receipt.artifactPackages.agent.includes("@aws-sdk/client-bedrock-runtime"));
  assert(receipt.artifactPackages.authority.includes("pg"));
  assert(receipt.artifactPackages.signer.includes("@aws-sdk/client-kms"));
  assert(
    receipt.artifactPackages.privateRecoveryQuery.includes(
      "@aws-sdk/client-secrets-manager"
    )
  );
  assert(
    receipt.artifactPackages.privateRecoveryQuery.includes(
      "@aws-sdk/client-dynamodb"
    )
  );
  assert(
    receipt.artifactPackages.evidenceProvider.includes(
      "@aws-sdk/client-cloudformation"
    )
  );
  assert(
    receipt.artifactPackages.evidenceProvider.includes(
      "@aws-sdk/client-apigatewayv2"
    )
  );
});

test("metafile package extraction is sorted, unique, and scoped", () => {
  assert.deepEqual(
    packageNamesFromMetafile({
      inputs: {
        "infra/aws/lambda/demo.js": { bytes: 1 },
        "node_modules/pg/lib/index.js": { bytes: 1 },
        "node_modules/@aws-sdk/core/dist-cjs/index.js": { bytes: 1 },
        "node_modules/pg/lib/client.js": { bytes: 1 }
      }
    }),
    ["@aws-sdk/core", "pg"]
  );
});

test("metafile package extraction rejects nested dependency ambiguity", () => {
  assert.throws(
    () =>
      packageNamesFromMetafile({
        inputs: {
          "node_modules/outer/node_modules/inner/index.js": { bytes: 1 }
        }
      }),
    /nested bundle dependency requires explicit support/
  );
});
