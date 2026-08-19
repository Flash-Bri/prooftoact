import crypto from "node:crypto";

import {
  verifyFreshPrimaryCredentialCustodyPlan
} from "./prepare-fresh-primary-credential-custody.js";
import {
  validateFreshPrimaryCredentialBundle
} from "./bootstrap-fresh-primary.js";

const HEX_64 = /^[0-9a-f]{64}$/u;
const SECRET_SUFFIX = /-[A-Za-z0-9]{6}$/u;
const ASSUMED_WRITER =
  /^arn:aws:sts::([0-9]{12}):assumed-role\/ProofToActFreshCredentialWriter-([0-9a-f]{16})\/([A-Za-z0-9+=,.@_-]{2,64})$/u;
const ASSUMED_USER = /^(AROA[A-Z0-9]{16}):([A-Za-z0-9+=,.@_-]{2,64})$/u;
const WRITER_TARGETS = Object.freeze([
  "auditor", "cloudApi", "credential", "mcp", "publisher"
]);
const RUNTIME_TARGETS = Object.freeze(["admin", "signer"]);
const MAXIMUM_BYTES = Object.freeze({
  auditor: 16 * 1024,
  cloudApi: 16 * 1024,
  credential: 64 * 1024,
  mcp: 16 * 1024,
  publisher: 16 * 1024
});
const PURPOSES = Object.freeze({
  admin: "FreshBootstrapAdmin",
  auditor: "FreshClusterAuditor",
  cloudApi: "FreshPrimaryCloudApi",
  credential: "FreshPrimaryRuntimeCredentials",
  mcp: "ManagedMcpReadOnly",
  publisher: "RecoveryPublisher",
  signer: "FreshRecoveryPublisherSigner"
});
const LOGICAL_IDS = Object.freeze({
  admin: "FreshPrimaryAdminSecret",
  auditor: "FreshClusterAuditorSecret",
  cloudApi: "FreshPrimaryCloudApiSecret",
  credential: "FreshPrimaryRuntimeCredentialsSecret",
  mcp: "ManagedMcpSecret",
  publisher: "RecoveryPublisherSecret",
  signer: "FreshPrimaryRecoverySignerSecret"
});

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, expected) {
  return plainObject(value) && Object.keys(value).sort().join("\n") ===
    [...expected].sort().join("\n");
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (plainObject(value)) {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function digest(value) {
  return sha256(Buffer.from(`${canonicalJson(value)}\n`, "utf8"));
}

function domainDigest(domain, fields) {
  return sha256(Buffer.from(`${domain}\n${fields.join("\n")}\n`, "utf8"));
}

function normalizeValues(values, expectedDigests) {
  const code = "FRESH_CREDENTIAL_VALUES_REJECTED";
  requireCondition(exactKeys(values, WRITER_TARGETS) &&
    exactKeys(expectedDigests, WRITER_TARGETS), code);
  const accepted = {};
  for (const name of WRITER_TARGETS) {
    const value = values[name];
    requireCondition(typeof value === "string" &&
      Buffer.byteLength(value, "utf8") > 0 &&
      Buffer.byteLength(value, "utf8") <= MAXIMUM_BYTES[name] &&
      HEX_64.test(expectedDigests[name] ?? "") &&
      sha256(Buffer.from(value, "utf8")) === expectedDigests[name], code);
    if (name === "credential") {
      let parsed;
      try {
        parsed = JSON.parse(value);
      } catch {
        reject(code);
      }
      try {
        validateFreshPrimaryCredentialBundle(parsed);
      } catch {
        reject(code);
      }
    } else {
      requireCondition(value.length >= 20 && value.length <= 4096 &&
        !/[\u0000-\u0020\u007f]/u.test(value), code);
    }
    accepted[name] = value;
  }
  requireCondition(values.auditor !== values.cloudApi, code);
  return Object.freeze(accepted);
}

function normalizeArns(value, plan) {
  const code = "FRESH_CREDENTIAL_ARNS_REJECTED";
  const names = [...WRITER_TARGETS, ...RUNTIME_TARGETS].sort();
  requireCondition(exactKeys(value, names), code);
  const accepted = {};
  for (const name of names) {
    const arn = value[name];
    const pattern = plan.secretArnPatterns[name];
    const prefix = pattern.slice(0, -6);
    requireCondition(typeof arn === "string" && arn.startsWith(prefix) &&
      arn.length === pattern.length && SECRET_SUFFIX.test(arn), code);
    accepted[name] = arn;
  }
  requireCondition(new Set(Object.values(accepted)).size === names.length,
    code);
  return Object.freeze(accepted);
}

function normalizeCallerIdentity(value, plan) {
  const code = "FRESH_CREDENTIAL_WRITER_CALLER_REJECTED";
  const arn = ASSUMED_WRITER.exec(value?.Arn ?? "");
  const user = ASSUMED_USER.exec(value?.UserId ?? "");
  requireCondition(value?.Account === plan.accountId && arn && user &&
    arn[1] === plan.accountId && arn[2] === plan.operationToken &&
    arn[3] === plan.writerSessionName && user[2] === plan.writerSessionName,
  code);
  return Object.freeze({
    accountId: plan.accountId,
    assumedRoleArnSha256: sha256(value.Arn),
    roleId: user[1],
    roleName: plan.writerRoleName,
    sessionName: plan.writerSessionName
  });
}

function expectedTags(plan, name) {
  return Object.freeze({
    OperationId: plan.operationId,
    Project: "ProofToAct",
    Purpose: PURPOSES[name]
  });
}

function tagMap(tags, code, plan, name) {
  requireCondition(Array.isArray(tags), code);
  const accepted = {};
  const system = {};
  for (const entry of tags) {
    requireCondition(exactKeys(entry, ["Key", "Value"]) &&
      typeof entry.Key === "string" && typeof entry.Value === "string", code);
    const target = entry.Key.startsWith("aws:") ? system : accepted;
    requireCondition(!Object.hasOwn(target, entry.Key), code);
    target[entry.Key] = entry.Value;
  }
  if (Object.keys(system).length > 0) {
    requireCondition(canonicalJson(system) === canonicalJson({
      "aws:cloudformation:logical-id": LOGICAL_IDS[name],
      "aws:cloudformation:stack-id": system["aws:cloudformation:stack-id"],
      "aws:cloudformation:stack-name": plan.stackName
    }) && typeof system["aws:cloudformation:stack-id"] === "string" &&
      system["aws:cloudformation:stack-id"].startsWith(
        `arn:aws:cloudformation:us-east-1:${plan.accountId}:stack/` +
        `${plan.stackName}/`
      ), code);
  }
  return accepted;
}

function normalizeDescription(value, plan, name, arn) {
  const code = "FRESH_CREDENTIAL_DESCRIPTION_REJECTED";
  requireCondition(value?.ARN === arn && value.Name === plan.secretNames[name] &&
    arn.endsWith(`:${value.Name}-${arn.slice(-6)}`) &&
    value.DeletedDate === undefined && value.RotationEnabled !== true &&
    plainObject(value.VersionIdsToStages) && value.KmsKeyId === undefined &&
    value.OwningService === undefined && value.PrimaryRegion === undefined &&
    (value.ReplicationStatus === undefined ||
      Array.isArray(value.ReplicationStatus) &&
      value.ReplicationStatus.length === 0) &&
    canonicalJson(tagMap(value.Tags, code, plan, name)) ===
      canonicalJson(expectedTags(plan, name)), code);
  return value.VersionIdsToStages;
}

function normalizeResourcePolicy(value, arn) {
  requireCondition(value?.ARN === arn && value.ResourcePolicy === undefined,
    "FRESH_CREDENTIAL_RESOURCE_POLICY_REJECTED");
}

async function listAllVersions(provider, arn) {
  const code = "FRESH_CREDENTIAL_VERSION_LIST_REJECTED";
  const versions = {};
  const observedTokens = new Set();
  let nextToken = null;
  for (let page = 0; page < 100; page += 1) {
    const response = await provider.listSecretVersions({ arn, nextToken });
    requireCondition(response?.ARN === arn &&
      Array.isArray(response.Versions), code);
    for (const version of response.Versions) {
      requireCondition(plainObject(version) &&
        typeof version.VersionId === "string" &&
        /^[A-Za-z0-9_-]{32,64}$/u.test(version.VersionId) &&
        Array.isArray(version.VersionStages) &&
        version.VersionStages.every((stage) => typeof stage === "string") &&
        !Object.hasOwn(versions, version.VersionId), code);
      versions[version.VersionId] = [...version.VersionStages];
    }
    if (response.NextToken === undefined) return Object.freeze(versions);
    requireCondition(typeof response.NextToken === "string" &&
      response.NextToken.length > 0 &&
      !observedTokens.has(response.NextToken), code);
    observedTokens.add(response.NextToken);
    nextToken = response.NextToken;
  }
  reject(code);
}

function versionId(plan, name, arn, valueSha256) {
  return domainDigest(
    "prooftoact-fresh-primary-credential-version-v1",
    [
      plan.planSha256,
      plan.operationId,
      name,
      arn,
      valueSha256
    ]
  );
}

function runtimeVersionId(plan, name, arn) {
  requireCondition(RUNTIME_TARGETS.includes(name),
    "FRESH_CREDENTIAL_RUNTIME_VERSION_REJECTED");
  return domainDigest(
    "prooftoact-fresh-primary-runtime-secret-version-v1",
    [
      plan.planSha256,
      plan.operationId,
      name,
      arn,
      plan.sourceCommit,
      plan.treeDigest
    ]
  );
}

function canonicalInstant(value, code) {
  const milliseconds = Date.parse(value);
  requireCondition(typeof value === "string" && Number.isFinite(milliseconds) &&
    new Date(milliseconds).toISOString() === value, code);
  return milliseconds;
}

function normalizeExpectedDigests(value) {
  requireCondition(exactKeys(value, WRITER_TARGETS) &&
    Object.values(value).every((item) => HEX_64.test(item ?? "")),
  "FRESH_CREDENTIAL_APPROVAL_DIGESTS_REJECTED");
  return Object.freeze({ ...value });
}

export function buildFreshPrimaryCredentialSealApproval({
  approvedAt,
  expectedValueSha256,
  expiresAt,
  operatorAuthorizationSha256,
  plan: rawPlan,
  secretArns
}) {
  const code = "FRESH_CREDENTIAL_APPROVAL_BUILD_REJECTED";
  const plan = verifyFreshPrimaryCredentialCustodyPlan(rawPlan);
  const arns = normalizeArns(secretArns, plan);
  const digests = normalizeExpectedDigests(expectedValueSha256);
  const approved = canonicalInstant(approvedAt, code);
  const expires = canonicalInstant(expiresAt, code);
  requireCondition(approved < expires && expires - approved <= 60 * 60 * 1000 &&
    HEX_64.test(operatorAuthorizationSha256 ?? "") &&
    operatorAuthorizationSha256 === plan.operatorAuthorizationSha256, code);
  return Object.freeze({
    schemaVersion: "prooftoact.fresh-primary-credential-seal-approval.v1",
    status: "APPROVED_ONE_SHOT_FIVE_VERSION_SEAL",
    accountId: plan.accountId,
    approvedAt,
    custodyPlanSha256: plan.planSha256,
    expiresAt,
    operationId: plan.operationId,
    operatorAuthorizationSha256,
    runtimeTargetBindings: Object.fromEntries(RUNTIME_TARGETS.map((name) => [
      name,
      {
        expectedInitialVersionCount: 0,
        secretArnSha256: sha256(arns[name]),
        targetVersionIdSha256: sha256(runtimeVersionId(
          plan, name, arns[name]
        ))
      }
    ])),
    secretBindings: Object.fromEntries(WRITER_TARGETS.map((name) => [
      name,
      {
        clientRequestToken: versionId(plan, name, arns[name], digests[name]),
        expectedValueSha256: digests[name],
        secretArnSha256: sha256(arns[name])
      }
    ])),
    sourceCommit: plan.sourceCommit,
    templateSha256: plan.templateSha256,
    treeDigest: plan.treeDigest,
    writerRoleArnSha256: sha256(plan.writerRoleArn)
  });
}

export function validateFreshPrimaryCredentialSealApproval(
  value,
  { clock = Date.now, plan, secretArns }
) {
  const code = "FRESH_CREDENTIAL_APPROVAL_REJECTED";
  requireCondition(typeof clock === "function" && plainObject(value), code);
  let rebuilt;
  try {
    rebuilt = buildFreshPrimaryCredentialSealApproval({
      approvedAt: value.approvedAt,
      expectedValueSha256: Object.fromEntries(WRITER_TARGETS.map((name) =>
        [name, value.secretBindings?.[name]?.expectedValueSha256])),
      expiresAt: value.expiresAt,
      operatorAuthorizationSha256: value.operatorAuthorizationSha256,
      plan,
      secretArns
    });
  } catch {
    reject(code);
  }
  const now = clock();
  requireCondition(Number.isFinite(now) &&
    canonicalJson(rebuilt) === canonicalJson(value) &&
    canonicalInstant(value.approvedAt, code) <= now &&
    now < canonicalInstant(value.expiresAt, code), code);
  return Object.freeze({
    ...rebuilt,
    approvalSha256: digest(rebuilt)
  });
}

function normalizeSecretReadback(value, arn, token, expectedValueSha256) {
  const code = "FRESH_CREDENTIAL_VERSION_READBACK_REJECTED";
  requireCondition(value?.ARN === arn && value.VersionId === token &&
    Array.isArray(value.VersionStages) &&
    canonicalJson(value.VersionStages) === canonicalJson(["AWSCURRENT"]) &&
    typeof value.SecretString === "string" &&
    !Object.hasOwn(value, "SecretBinary") &&
    sha256(Buffer.from(value.SecretString, "utf8")) === expectedValueSha256,
  code);
  const created = value.CreatedDate instanceof Date
    ? value.CreatedDate.getTime()
    : Date.parse(value.CreatedDate);
  requireCondition(Number.isFinite(created), code);
  return Object.freeze({
    createdAt: new Date(created).toISOString(),
    secretArnSha256: sha256(arn),
    secretValueSha256: expectedValueSha256,
    secretVersionIdSha256: sha256(token),
    versionStage: "AWSCURRENT"
  });
}

async function inspect(provider, plan, name, arn) {
  const [description, resourcePolicy, listedVersions] = await Promise.all([
    provider.describeSecret({ arn }),
    provider.getSecretResourcePolicy({ arn }),
    listAllVersions(provider, arn)
  ]);
  const versions = normalizeDescription(description, plan, name, arn);
  normalizeResourcePolicy(resourcePolicy, arn);
  requireCondition(canonicalJson(versions) === canonicalJson(listedVersions),
    "FRESH_CREDENTIAL_VERSION_INVENTORY_REJECTED");
  return Object.freeze({ description, versions: listedVersions });
}

async function readExact(provider, arn, token, expectedValueSha256) {
  const readback = await provider.readSecretVersion({ arn, versionId: token });
  requireCondition(readback !== null,
    "FRESH_CREDENTIAL_VERSION_READBACK_REJECTED");
  return normalizeSecretReadback(
    readback, arn, token, expectedValueSha256
  );
}

async function convergeOne({
  arn,
  expectedValueSha256,
  name,
  plan,
  provider,
  value
}) {
  const token = versionId(plan, name, arn, expectedValueSha256);
  const before = await inspect(provider, plan, name, arn);
  const versionKeys = Object.keys(before.versions);
  if (versionKeys.length === 1 && versionKeys[0] === token &&
    canonicalJson(before.versions[token]) === canonicalJson(["AWSCURRENT"])) {
    return Object.freeze({
      ...await readExact(provider, arn, token, expectedValueSha256),
      dispatchCount: 0,
      reconciledExistingVersion: true
    });
  }
  requireCondition(versionKeys.length === 0,
    "FRESH_CREDENTIAL_PRESTATE_REJECTED");
  try {
    await provider.putSecretVersion({
      arn,
      clientRequestToken: token,
      secretString: value
    });
  } catch (cause) {
    try {
      const reconciled = await readExact(
        provider, arn, token, expectedValueSha256
      );
      return Object.freeze({
        ...reconciled,
        dispatchCount: 1,
        reconciledAcknowledgementLoss: true
      });
    } catch (readbackCause) {
      reject("FRESH_CREDENTIAL_VERSION_UNKNOWN_DO_NOT_CHANGE_TOKEN", {
        cause,
        readbackCause
      });
    }
  }
  const after = await inspect(provider, plan, name, arn);
  requireCondition(Object.keys(after.versions).length === 1 &&
    canonicalJson(after.versions) === canonicalJson({
      [token]: ["AWSCURRENT"]
    }), "FRESH_CREDENTIAL_VERSION_COUNT_REJECTED");
  return Object.freeze({
    ...await readExact(provider, arn, token, expectedValueSha256),
    dispatchCount: 1,
    reconciledAcknowledgementLoss: false
  });
}

export async function sealFreshPrimaryCredentialCustody({
  approval: rawApproval,
  clock = Date.now,
  plan: rawPlan,
  provider,
  secretArns,
  values
}) {
  const code = "FRESH_CREDENTIAL_SEAL_REJECTED";
  requireCondition(provider && [
    "describeSecret",
    "getCallerIdentity",
    "getSecretResourcePolicy",
    "listSecretVersions",
    "putSecretVersion",
    "readSecretVersion"
  ].every((name) => typeof provider[name] === "function"), code);
  const plan = verifyFreshPrimaryCredentialCustodyPlan(rawPlan);
  const arns = normalizeArns(secretArns, plan);
  const approval = validateFreshPrimaryCredentialSealApproval(rawApproval, {
    clock,
    plan,
    secretArns: arns
  });
  const expectedValueSha256 = Object.freeze(Object.fromEntries(
    WRITER_TARGETS.map((name) =>
      [name, approval.secretBindings[name].expectedValueSha256])
  ));
  const material = normalizeValues(values, expectedValueSha256);
  const caller = normalizeCallerIdentity(await provider.getCallerIdentity(),
    plan);

  for (const name of RUNTIME_TARGETS) {
    const prestate = await inspect(provider, plan, name, arns[name]);
    requireCondition(Object.keys(prestate.versions).length === 0,
      "FRESH_CREDENTIAL_RUNTIME_TARGET_NOT_EMPTY");
  }

  // Complete the seven-container preflight before the first value mutation.
  // This prevents a later contradictory or attacker-populated container from
  // being discovered only after earlier credentials have already been sealed.
  for (const name of WRITER_TARGETS) {
    const token = versionId(
      plan, name, arns[name], expectedValueSha256[name]
    );
    const prestate = await inspect(provider, plan, name, arns[name]);
    const keys = Object.keys(prestate.versions);
    requireCondition(keys.length === 0 ||
      keys.length === 1 && keys[0] === token &&
      canonicalJson(prestate.versions[token]) ===
        canonicalJson(["AWSCURRENT"]),
    "FRESH_CREDENTIAL_PRESTATE_REJECTED");
    if (keys.length === 1) {
      await readExact(
        provider, arns[name], token, expectedValueSha256[name]
      );
    }
  }

  const sealed = {};
  for (const name of WRITER_TARGETS) {
    sealed[name] = await convergeOne({
      arn: arns[name],
      expectedValueSha256: expectedValueSha256[name],
      name,
      plan,
      provider,
      value: material[name]
    });
  }

  for (const name of RUNTIME_TARGETS) {
    const poststate = await inspect(provider, plan, name, arns[name]);
    requireCondition(Object.keys(poststate.versions).length === 0,
      "FRESH_CREDENTIAL_RUNTIME_TARGET_NOT_EMPTY");
  }
  for (const name of WRITER_TARGETS) {
    const token = versionId(
      plan, name, arns[name], expectedValueSha256[name]
    );
    const poststate = await inspect(provider, plan, name, arns[name]);
    requireCondition(canonicalJson(poststate.versions) === canonicalJson({
      [token]: ["AWSCURRENT"]
    }), "FRESH_CREDENTIAL_FINAL_READBACK_REJECTED");
    await readExact(provider, arns[name], token, expectedValueSha256[name]);
  }

  const receipt = {
    schemaVersion: "prooftoact.fresh-primary-credential-seal-receipt.v1",
    status: "EXACT_FIVE_VERSIONS_SEALED_TWO_TARGETS_EMPTY",
    accountId: plan.accountId,
    approvalSha256: approval.approvalSha256,
    caller,
    custodyPlanSha256: plan.planSha256,
    immutableVersionCount: 5,
    operationId: plan.operationId,
    runtimeGeneratedTargetCount: 2,
    runtimeGeneratedTargetsEmpty: true,
    sealed,
    sourceCommit: plan.sourceCommit,
    templateSha256: plan.templateSha256,
    treeDigest: plan.treeDigest,
    writerRoleArnSha256: sha256(plan.writerRoleArn)
  };
  return Object.freeze({ ...receipt, receiptSha256: digest(receipt) });
}

export const __test = Object.freeze({
  MAXIMUM_BYTES,
  PURPOSES,
  RUNTIME_TARGETS,
  WRITER_TARGETS,
  canonicalJson,
  digest,
  expectedTags,
  normalizeArns,
  normalizeCallerIdentity,
  normalizeDescription,
  normalizeSecretReadback,
  normalizeValues,
  runtimeVersionId,
  validateFreshPrimaryCredentialSealApproval,
  listAllVersions,
  versionId
});
