import assert from "node:assert/strict";
import test from "node:test";

import {
  assertAwsSdkEvidenceEnvironment,
  assertNoAwsEndpointOverrides,
  explicitAwsCredentials,
  isolatedAwsCliEnvironment,
  isolatedEvidenceProcessEnvironment,
  validateAwsEvidenceCaller
} from "../src/cloud/aws-evidence-identity.js";

const ACCOUNT_ID = "111111111111";
const ROLE_ARN =
  `arn:aws:iam::${ACCOUNT_ID}:role/AuthorityRaceCallerRole`;
const CALLER_ARN =
  `arn:aws:sts::${ACCOUNT_ID}:assumed-role/` +
  "AuthorityRaceCallerRole/release-proof";
const CALLER_USER_ID = "AROATIDEPROOFROLE1:release-proof";
const BINDING_CONTEXT = Object.freeze({
  purpose: "test-authority-race",
  sourceCommit: "a".repeat(40)
});

function environment(overrides = {}) {
  return {
    PATH: "/usr/bin",
    LANG: "en_US.UTF-8",
    HOME: "/private/home",
    DATABASE_URL: "postgresql://private",
    AWS_ACCESS_KEY_ID: "ASIAEXAMPLE12345678",
    AWS_SECRET_ACCESS_KEY: "secret-example-value",
    AWS_SESSION_TOKEN: "session-example-value",
    AWS_PROFILE: "unreviewed-profile",
    ...overrides
  };
}

test("AWS evidence environment rejects every endpoint override form", () => {
  assert.doesNotThrow(() => assertNoAwsEndpointOverrides(environment()));
  for (const name of [
    "AWS_ENDPOINT_URL",
    "AWS_ENDPOINT_URL_STS",
    "AWS_ENDPOINT_URL_LAMBDA"
  ]) {
    assert.throws(
      () => assertNoAwsEndpointOverrides(environment({ [name]: "" })),
      /AWS_EVIDENCE_ENDPOINT_OVERRIDE/
    );
  }
});

test("AWS SDK evidence rejects profile, proxy, and custom-CA injection", () => {
  for (const name of [
    "AWS_CONFIG_FILE",
    "AWS_DEFAULTS_MODE",
    "AWS_PROFILE",
    "AWS_RETRY_MODE",
    "AWS_AUTH_SCHEME_PREFERENCE",
    "AWS_SIGV4A_SIGNING_REGION_SET",
    "AWS_USE_DUALSTACK_ENDPOINT",
    "AWS_USE_FIPS_ENDPOINT",
    "AWS_CA_BUNDLE",
    "HTTPS_PROXY",
    "http_proxy",
    "NODE_EXTRA_CA_CERTS",
    "NODE_DEBUG",
    "NODE_OPTIONS",
    "NODE_TLS_REJECT_UNAUTHORIZED"
  ]) {
    assert.throws(
      () => assertAwsSdkEvidenceEnvironment({ [name]: "/tmp/injected" }),
      /AWS_EVIDENCE_SDK_ENVIRONMENT/
    );
  }
  assert.doesNotThrow(() =>
    assertAwsSdkEvidenceEnvironment({
      AWS_ACCESS_KEY_ID: "ASIAEXAMPLE12345678",
      AWS_SECRET_ACCESS_KEY: "secret-example-value",
      AWS_SESSION_TOKEN: "session-example-value"
    })
  );
});

test("non-AWS evidence children receive no credentials or identity expectations", () => {
  const isolated = isolatedEvidenceProcessEnvironment({
    ...environment(),
    AWS_EVIDENCE_EXPECTED_ACCOUNT_ID: ACCOUNT_ID,
    NODE_OPTIONS: "--require=/tmp/inject.js"
  });
  assert.equal(isolated.PATH, "/usr/bin");
  assert.equal(isolated.AWS_ACCESS_KEY_ID, undefined);
  assert.equal(isolated.AWS_SECRET_ACCESS_KEY, undefined);
  assert.equal(isolated.AWS_SESSION_TOKEN, undefined);
  assert.equal(isolated.AWS_EVIDENCE_EXPECTED_ACCOUNT_ID, undefined);
  assert.equal(isolated.NODE_OPTIONS, undefined);
  assert.equal(isolated.GIT_CONFIG_GLOBAL, "/dev/null");
  assert.equal(isolated.GIT_NO_LAZY_FETCH, "1");
  assert.equal(isolated.GIT_NO_REPLACE_OBJECTS, "1");
});

test("AWS CLI evidence environment retains only explicit credentials and safe process inputs", () => {
  const isolated = isolatedAwsCliEnvironment(environment(), {
    requireSessionToken: true
  });
  assert.equal(isolated.PATH, "/usr/bin");
  assert.equal(isolated.LANG, "en_US.UTF-8");
  assert.equal(isolated.HOME, undefined);
  assert.equal(isolated.DATABASE_URL, undefined);
  assert.equal(isolated.AWS_PROFILE, undefined);
  assert.equal(isolated.AWS_CONFIG_FILE, "/dev/null");
  assert.equal(isolated.AWS_SHARED_CREDENTIALS_FILE, "/dev/null");
  assert.equal(isolated.AWS_IGNORE_CONFIGURED_ENDPOINT_URLS, "true");
  assert.equal(isolated.AWS_SESSION_TOKEN, "session-example-value");
});

test("explicit AWS evidence credentials fail closed without an assumed-role session token", () => {
  assert.throws(
    () =>
      explicitAwsCredentials(
        environment({ AWS_SESSION_TOKEN: undefined }),
        { requireSessionToken: true }
      ),
    /AWS_EVIDENCE_SESSION_TOKEN/
  );
});

test("caller binding accepts only the exact expected account and principal", () => {
  const binding = validateAwsEvidenceCaller(
    {
      Account: ACCOUNT_ID,
      Arn: CALLER_ARN,
      UserId: CALLER_USER_ID
    },
    {
      expectedAccountId: ACCOUNT_ID,
      expectedPrincipalArn: ROLE_ARN,
      expectedCallerArn: CALLER_ARN,
      expectedCallerUserId: CALLER_USER_ID,
      bindingContext: BINDING_CONTEXT
    }
  );
  assert.match(binding.callerIdentityDigest, /^[0-9a-f]{64}$/);
  assert.equal(binding.callerIdentityDigest, binding.expectedIdentityDigest);
  assert.match(binding.expectedPrincipalDigest, /^[0-9a-f]{64}$/);
  assert.match(binding.principalIdDigest, /^[0-9a-f]{64}$/);
  assert.match(binding.contextDigest, /^[0-9a-f]{64}$/);
  assert.match(binding.bindingDigest, /^[0-9a-f]{64}$/);
  assert.equal(binding.principalType, "assumed-role");

  const otherContext = validateAwsEvidenceCaller(
    {
      Account: ACCOUNT_ID,
      Arn: CALLER_ARN,
      UserId: CALLER_USER_ID
    },
    {
      expectedAccountId: ACCOUNT_ID,
      expectedPrincipalArn: ROLE_ARN,
      expectedCallerArn: CALLER_ARN,
      expectedCallerUserId: CALLER_USER_ID,
      bindingContext: {
        ...BINDING_CONTEXT,
        sourceCommit: "c".repeat(40)
      }
    }
  );
  assert.notEqual(binding.contextDigest, otherContext.contextDigest);
  assert.notEqual(binding.bindingDigest, otherContext.bindingDigest);

  for (const identity of [
    {
      Account: "222222222222",
      Arn:
        "arn:aws:sts::222222222222:assumed-role/" +
        "AuthorityRaceCallerRole/release-proof",
      UserId: "AROATIDEPROOFROLE1:release-proof"
    },
    {
      Account: ACCOUNT_ID,
      Arn: `arn:aws:iam::${ACCOUNT_ID}:user/admin`,
      UserId: "AIDATIDEPROOF001"
    },
    {
      Account: ACCOUNT_ID,
      Arn:
        `arn:aws:sts::${ACCOUNT_ID}:assumed-role/` +
        "OtherRole/release-proof",
      UserId: "AROATIDEPROOFROLE1:release-proof"
    },
    {
      Account: ACCOUNT_ID,
      Arn:
        `arn:aws:sts::${ACCOUNT_ID}:assumed-role/` +
        "AuthorityRaceCallerRole/different-session",
      UserId: "AROATIDEPROOFROLE1:different-session"
    },
    {
      Account: ACCOUNT_ID,
      Arn: CALLER_ARN,
      UserId: "AROATIDEPROOFROLE1:different-session"
    }
  ]) {
    assert.throws(
      () =>
        validateAwsEvidenceCaller(identity, {
          expectedAccountId: ACCOUNT_ID,
          expectedPrincipalArn: ROLE_ARN,
          expectedCallerArn: CALLER_ARN,
          expectedCallerUserId: CALLER_USER_ID,
          bindingContext: BINDING_CONTEXT
        }),
      /AWS_EVIDENCE_CALLER_(?:ACCOUNT|ARN|USER)/
    );
  }

  assert.throws(
    () =>
      validateAwsEvidenceCaller(
        {
          Account: ACCOUNT_ID,
          Arn: CALLER_ARN,
          UserId: CALLER_USER_ID
        },
        {
          expectedAccountId: ACCOUNT_ID,
          expectedPrincipalArn:
            `arn:aws:iam::${ACCOUNT_ID}:role/path/AuthorityRaceCallerRole`,
          expectedCallerArn: CALLER_ARN,
          expectedCallerUserId: CALLER_USER_ID,
          bindingContext: BINDING_CONTEXT
        }
      ),
    /AWS_EVIDENCE_EXPECTED_PRINCIPAL/
  );
});

test("assumed-role caller binding links STS UserId to the censused RoleId", () => {
  const identity = {
    Account: "111111111111",
    Arn: "arn:aws:sts::111111111111:assumed-role/example/session",
    UserId: "AROATIDEPROOFROLE1:session"
  };
  const input = {
    expectedAccountId: "111111111111",
    expectedPrincipalArn: "arn:aws:iam::111111111111:role/example",
    expectedCallerArn: identity.Arn,
    expectedCallerUserId: identity.UserId,
    expectedRoleId: "AROATIDEPROOFROLE1",
    bindingContext: { purpose: "role-id-test" }
  };
  assert.doesNotThrow(() => validateAwsEvidenceCaller(identity, input));
  assert.throws(
    () =>
      validateAwsEvidenceCaller(identity, {
        ...input,
        expectedRoleId: "AROATIDEPROOFROLE2"
      }),
    /AWS_EVIDENCE_CALLER_ROLE_ID/
  );
});

test("caller binding supports an exact IAM user for preflight", () => {
  const userArn = `arn:aws:iam::${ACCOUNT_ID}:user/tideproof-deployer`;
  const binding = validateAwsEvidenceCaller(
    {
      Account: ACCOUNT_ID,
      Arn: userArn,
      UserId: "AIDATIDEPROOF001"
    },
    {
      expectedAccountId: ACCOUNT_ID,
      expectedPrincipalArn: userArn,
      expectedCallerArn: userArn,
      expectedCallerUserId: "AIDATIDEPROOF001",
      bindingContext: {
        purpose: "test-preflight",
        sourceCommit: "b".repeat(40)
      }
    }
  );
  assert.equal(binding.principalType, "iam-user");
});
