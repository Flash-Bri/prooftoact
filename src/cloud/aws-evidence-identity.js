import crypto from "node:crypto";

const ACCOUNT_ID = /^\d{12}$/;
const ENDPOINT_OVERRIDE = /^AWS_ENDPOINT_URL(?:_.+)?$/i;
const IAM_USER_ID = /^AIDA[A-Z0-9]{12,124}$/;
const IAM_USER_RESOURCE =
  /^(?:[\x21-\x2E\x30-\x7E]+\/)*[A-Za-z0-9+=,.@_-]{1,64}$/;
const SESSION_NAME = /^[A-Za-z0-9+=,.@_-]{2,64}$/;
const UNSAFE_SDK_ENVIRONMENT = new Set([
  "ALL_PROXY",
  "AWS_CA_BUNDLE",
  "AWS_CONFIG_FILE",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
  "AWS_CONTAINER_CREDENTIALS_FULL_URI",
  "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
  "AWS_DEFAULTS_MODE",
  "AWS_DEFAULT_PROFILE",
  "AWS_AUTH_SCHEME_PREFERENCE",
  "AWS_PROFILE",
  "AWS_ROLE_ARN",
  "AWS_ROLE_SESSION_NAME",
  "AWS_RETRY_MODE",
  "AWS_SDK_LOAD_CONFIG",
  "AWS_SIGV4A_SIGNING_REGION_SET",
  "AWS_SHARED_CREDENTIALS_FILE",
  "AWS_USE_DUALSTACK_ENDPOINT",
  "AWS_USE_FIPS_ENDPOINT",
  "AWS_WEB_IDENTITY_TOKEN_FILE",
  "CURL_CA_BUNDLE",
  "HTTPS_PROXY",
  "HTTP_PROXY",
  "NODE_EXTRA_CA_CERTS",
  "NODE_DEBUG",
  "NODE_OPTIONS",
  "NODE_TLS_REJECT_UNAUTHORIZED",
  "NODE_V8_COVERAGE",
  "NO_PROXY",
  "REQUESTS_CA_BUNDLE",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE"
]);
const SAFE_PROCESS_ENVIRONMENT = new Set([
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "NO_COLOR",
  "PATH",
  "TMPDIR"
]);

function requireCondition(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(
        ([key, nested]) =>
          `${JSON.stringify(key)}:${canonicalJson(nested)}`
      )
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

export function assertNoAwsEndpointOverrides(environment) {
  requireCondition(
    environment && typeof environment === "object",
    "AWS_EVIDENCE_ENVIRONMENT"
  );
  const override = Object.keys(environment).find((name) =>
    ENDPOINT_OVERRIDE.test(name)
  );
  requireCondition(!override, "AWS_EVIDENCE_ENDPOINT_OVERRIDE");
}

export function assertAwsSdkEvidenceEnvironment(environment) {
  assertNoAwsEndpointOverrides(environment);
  const unsafe = Object.keys(environment).find(
    (name) => {
      if (
        !UNSAFE_SDK_ENVIRONMENT.has(name.toUpperCase()) ||
        environment[name] === undefined ||
        String(environment[name]).length === 0
      ) {
        return false;
      }
      if (
        ["AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"].includes(
          name
        ) &&
        environment[name] === "/dev/null"
      ) {
        return false;
      }
      return true;
    }
  );
  requireCondition(!unsafe, "AWS_EVIDENCE_SDK_ENVIRONMENT");
}

export function explicitAwsCredentials(
  environment,
  { requireSessionToken = false } = {}
) {
  assertNoAwsEndpointOverrides(environment);
  const accessKeyId = environment.AWS_ACCESS_KEY_ID;
  const secretAccessKey = environment.AWS_SECRET_ACCESS_KEY;
  const sessionToken = environment.AWS_SESSION_TOKEN;
  requireCondition(
    typeof accessKeyId === "string" && accessKeyId.length >= 16,
    "AWS_EVIDENCE_ACCESS_KEY"
  );
  requireCondition(
    typeof secretAccessKey === "string" && secretAccessKey.length >= 16,
    "AWS_EVIDENCE_SECRET_KEY"
  );
  requireCondition(
    !requireSessionToken ||
      (typeof sessionToken === "string" && sessionToken.length >= 16),
    "AWS_EVIDENCE_SESSION_TOKEN"
  );
  return {
    accessKeyId,
    secretAccessKey,
    ...(typeof sessionToken === "string" && sessionToken.length > 0
      ? { sessionToken }
      : {})
  };
}

export function isolatedAwsCliEnvironment(
  sourceEnvironment,
  { region = "us-east-1", requireSessionToken = false } = {}
) {
  const credentials = explicitAwsCredentials(sourceEnvironment, {
    requireSessionToken
  });
  requireCondition(
    typeof region === "string" && /^[a-z]{2}-[a-z]+-\d$/.test(region),
    "AWS_EVIDENCE_REGION"
  );
  const environment = Object.fromEntries(
    Object.entries(sourceEnvironment).filter(([name]) =>
      SAFE_PROCESS_ENVIRONMENT.has(name)
    )
  );
  return {
    ...environment,
    AWS_ACCESS_KEY_ID: credentials.accessKeyId,
    AWS_SECRET_ACCESS_KEY: credentials.secretAccessKey,
    ...(credentials.sessionToken
      ? { AWS_SESSION_TOKEN: credentials.sessionToken }
      : {}),
    AWS_CONFIG_FILE: "/dev/null",
    AWS_DEFAULT_REGION: region,
    AWS_EC2_METADATA_DISABLED: "true",
    AWS_IGNORE_CONFIGURED_ENDPOINT_URLS: "true",
    AWS_MAX_ATTEMPTS: "1",
    AWS_PAGER: "",
    AWS_REGION: region,
    AWS_RETRY_MODE: "standard",
    AWS_SHARED_CREDENTIALS_FILE: "/dev/null",
    AWS_STS_REGIONAL_ENDPOINTS: "regional"
  };
}

export function isolatedEvidenceProcessEnvironment(sourceEnvironment) {
  requireCondition(
    sourceEnvironment && typeof sourceEnvironment === "object",
    "AWS_EVIDENCE_ENVIRONMENT"
  );
  return {
    ...Object.fromEntries(
      Object.entries(sourceEnvironment).filter(([name]) =>
        SAFE_PROCESS_ENVIRONMENT.has(name)
      )
    ),
    AWS_CONFIG_FILE: "/dev/null",
    AWS_EC2_METADATA_DISABLED: "true",
    AWS_IGNORE_CONFIGURED_ENDPOINT_URLS: "true",
    AWS_PAGER: "",
    AWS_SHARED_CREDENTIALS_FILE: "/dev/null",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_NO_LAZY_FETCH: "1",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_TERMINAL_PROMPT: "0"
  };
}

function principalExpectation(expectedPrincipalArn) {
  const role =
    /^arn:aws:iam::(\d{12}):role\/([A-Za-z0-9+=,.@_-]{1,64})$/.exec(
      expectedPrincipalArn
    );
  if (role) {
    const [, accountId, roleName] = role;
    return {
      accountId,
      principalType: "assumed-role",
      acceptsCallerArn(actualArn) {
        const prefix = `arn:aws:sts::${accountId}:assumed-role/${roleName}/`;
        return (
          actualArn.startsWith(prefix) &&
          SESSION_NAME.test(actualArn.slice(prefix.length))
        );
      }
    };
  }
  const user = /^arn:aws:iam::(\d{12}):user\/(.{1,576})$/.exec(
    expectedPrincipalArn
  );
  if (user && IAM_USER_RESOURCE.test(user[2])) {
    const [, accountId] = user;
    return {
      accountId,
      principalType: "iam-user",
      acceptsCallerArn(actualArn) {
        return actualArn === expectedPrincipalArn;
      }
    };
  }
  throw new Error("AWS_EVIDENCE_EXPECTED_PRINCIPAL");
}

export function validateAwsEvidenceCaller(
  identity,
  {
    expectedAccountId,
    expectedPrincipalArn,
    expectedCallerArn,
    expectedCallerUserId,
    expectedRoleId,
    bindingContext
  }
) {
  requireCondition(
    ACCOUNT_ID.test(expectedAccountId),
    "AWS_EVIDENCE_EXPECTED_ACCOUNT"
  );
  requireCondition(
    identity &&
      typeof identity === "object" &&
      !Array.isArray(identity) &&
      Object.keys(identity).sort().join("\n") ===
        ["Account", "Arn", "UserId"].sort().join("\n"),
    "AWS_EVIDENCE_CALLER_SHAPE"
  );
  const expected = principalExpectation(expectedPrincipalArn);
  requireCondition(
    expected.accountId === expectedAccountId,
    "AWS_EVIDENCE_PRINCIPAL_ACCOUNT"
  );
  requireCondition(
    identity.Account === expectedAccountId,
    "AWS_EVIDENCE_CALLER_ACCOUNT"
  );
  requireCondition(
    typeof expectedCallerArn === "string" &&
      expected.acceptsCallerArn(expectedCallerArn),
    "AWS_EVIDENCE_EXPECTED_CALLER_ARN"
  );
  requireCondition(
    typeof expectedCallerUserId === "string" &&
      expectedCallerUserId.length >= 8 &&
      expectedCallerUserId.length <= 256,
    "AWS_EVIDENCE_EXPECTED_CALLER_USER"
  );
  requireCondition(
    identity.Arn === expectedCallerArn,
    "AWS_EVIDENCE_CALLER_ARN"
  );
  requireCondition(
    identity.UserId === expectedCallerUserId,
    "AWS_EVIDENCE_CALLER_USER"
  );
  let principalId;
  if (expected.principalType === "assumed-role") {
    const sessionName = identity.Arn.split("/").at(-1);
    const delimiter = identity.UserId.lastIndexOf(":");
    principalId = identity.UserId.slice(0, delimiter);
    requireCondition(
      delimiter > 0 &&
        /^[A-Z0-9]{16,128}$/.test(principalId) &&
        SESSION_NAME.test(sessionName) &&
        identity.UserId === `${principalId}:${sessionName}` &&
        (expectedRoleId === undefined || expectedRoleId === principalId),
      "AWS_EVIDENCE_CALLER_ROLE_ID"
    );
  } else {
    requireCondition(
      IAM_USER_ID.test(identity.UserId),
      "AWS_EVIDENCE_CALLER_USER_ID"
    );
    principalId = identity.UserId;
  }
  requireCondition(
    bindingContext &&
      typeof bindingContext === "object" &&
      !Array.isArray(bindingContext) &&
      Object.keys(bindingContext).length > 0,
    "AWS_EVIDENCE_BINDING_CONTEXT"
  );
  let canonicalContext;
  try {
    canonicalContext = canonicalJson(bindingContext);
  } catch {
    throw new Error("AWS_EVIDENCE_BINDING_CONTEXT");
  }
  requireCondition(
    typeof canonicalContext === "string" &&
      canonicalContext.length >= 2 &&
      canonicalContext.length <= 4096 &&
      !canonicalContext.includes("undefined"),
    "AWS_EVIDENCE_BINDING_CONTEXT"
  );
  const callerIdentityDigest = sha256(
    JSON.stringify({
      accountId: identity.Account,
      arn: identity.Arn,
      userId: identity.UserId
    })
  );
  const expectedIdentityDigest = sha256(
    JSON.stringify({
      accountId: expectedAccountId,
      arn: expectedCallerArn,
      userId: expectedCallerUserId
    })
  );
  requireCondition(
    callerIdentityDigest === expectedIdentityDigest,
    "AWS_EVIDENCE_CALLER_BINDING"
  );
  const expectedPrincipalDigest = sha256(expectedPrincipalArn);
  const principalIdDigest = sha256(principalId);
  const contextDigest = sha256(
    `tideproof.aws-evidence-context.v1\0${canonicalContext}`
  );
  const bindingDigest = sha256(
    [
      "tideproof.aws-evidence-caller-binding.v2",
      callerIdentityDigest,
      expectedIdentityDigest,
      expectedPrincipalDigest,
      principalIdDigest,
      contextDigest
    ].join("\0")
  );
  return Object.freeze({
    bindingDigest,
    callerIdentityDigest,
    contextDigest,
    expectedIdentityDigest,
    expectedPrincipalDigest,
    principalIdDigest,
    principalType: expected.principalType
  });
}

export const __test = Object.freeze({
  ENDPOINT_OVERRIDE,
  SAFE_PROCESS_ENVIRONMENT,
  UNSAFE_SDK_ENVIRONMENT
});
