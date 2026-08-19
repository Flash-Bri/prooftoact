import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const TEMPLATE_PATH = "infra/aws/fresh-primary-bootstrap-role-stack.json";
const TEMPLATE_SHA256 =
  "0ecab5c430720c7ec030dbd49e48abab3b9554cf2820368f17a3a8f89c13d08b";
const STACK_NAME = "prooftoact-fresh-primary-bootstrap-role";
const ROLE_NAME = "ProofToActFreshPrimaryBootstrap";
const REGION = "us-east-1";
const ACCOUNT = /^[0-9]{12}$/u;
const HEX_40 = /^[0-9a-f]{40}$/u;

function reject(code) {
  throw new Error(code);
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

function digestBytes(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function digest(value) {
  return digestBytes(Buffer.from(`${canonicalJson(value)}\n`, "utf8"));
}

function readReviewedTemplate() {
  const bytes = fs.readFileSync(path.join(ROOT, TEMPLATE_PATH));
  requireCondition(digestBytes(bytes) === TEMPLATE_SHA256,
    "FRESH_PRIMARY_ROLE_TEMPLATE_DIGEST_REJECTED");
  const template = JSON.parse(bytes.toString("utf8"));
  requireCondition(exactKeys(template.Resources, ["FreshPrimaryBootstrapRole"]) &&
    exactKeys(template.Outputs, ["FreshPrimaryBootstrapRoleArn"]) &&
    exactKeys(template.Parameters, ["GitHubOidcProviderArn"]) &&
    template.Resources.FreshPrimaryBootstrapRole.Type === "AWS::IAM::Role" &&
    template.Resources.FreshPrimaryBootstrapRole.Properties.RoleName ===
      ROLE_NAME,
  "FRESH_PRIMARY_ROLE_TEMPLATE_CONTRACT_REJECTED");
  return Object.freeze({ bytes, template });
}

export function prepareFreshPrimaryBootstrapRole({
  accountId,
  sourceCommit,
  treeDigest
}) {
  const code = "FRESH_PRIMARY_ROLE_PREPARE_REJECTED";
  requireCondition(ACCOUNT.test(accountId ?? "") &&
    HEX_40.test(sourceCommit ?? "") && HEX_40.test(treeDigest ?? ""), code);
  const reviewed = readReviewedTemplate();
  const oidcProviderArn = `arn:aws:iam::${accountId}:oidc-provider/` +
    "token.actions.githubusercontent.com";
  const plan = {
    schemaVersion: "prooftoact.fresh-primary-bootstrap-role-plan.v1",
    status: "READY_FOR_EXACT_CREATE_ONLY_APPLY",
    accountId,
    capabilities: ["CAPABILITY_NAMED_IAM"],
    createOnly: true,
    expectedOutput: {
      key: "FreshPrimaryBootstrapRoleArn",
      value: `arn:aws:iam::${accountId}:role/${ROLE_NAME}`
    },
    expectedResourceCount: 1,
    githubOidcProviderArn: oidcProviderArn,
    onFailure: "DELETE",
    region: REGION,
    requiredBootstrapAuthority: {
      cloudFormationActions: [
        "cloudformation:CreateStack",
        "cloudformation:DeleteStack",
        "cloudformation:DescribeStackEvents",
        "cloudformation:DescribeStacks",
        "cloudformation:GetTemplate",
        "cloudformation:ListStackResources",
        "cloudformation:UpdateTerminationProtection"
      ],
      cloudFormationCreateResource: "*",
      cloudFormationStackResource:
        `arn:aws:cloudformation:${REGION}:${accountId}:stack/${STACK_NAME}/*`,
      iamActions: [
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:DeleteRolePolicy",
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:ListRoleTags",
        "iam:PutRolePolicy",
        "iam:TagRole",
        "iam:UntagRole",
        "iam:UpdateAssumeRolePolicy",
        "iam:UpdateRoleDescription"
      ],
      iamResource: `arn:aws:iam::${accountId}:role/${ROLE_NAME}`,
      oidcReadActions: ["iam:GetOpenIDConnectProvider"],
      oidcResource: oidcProviderArn,
      passRoleExplicitlyAbsent: true
    },
    requiredStackTags: {
      Project: "ProofToAct"
    },
    roleName: ROLE_NAME,
    sourceCommit,
    stackName: STACK_NAME,
    templateBytes: reviewed.bytes.length,
    templatePath: TEMPLATE_PATH,
    templateSha256: TEMPLATE_SHA256,
    terminationProtection: true,
    treeDigest,
    updateAllowed: false
  };
  return Object.freeze({ ...plan, planSha256: digest(plan) });
}

export function verifyFreshPrimaryBootstrapRolePlan(value) {
  const rebuilt = prepareFreshPrimaryBootstrapRole({
    accountId: value?.accountId,
    sourceCommit: value?.sourceCommit,
    treeDigest: value?.treeDigest
  });
  requireCondition(canonicalJson(rebuilt) === canonicalJson(value),
    "FRESH_PRIMARY_ROLE_PLAN_REJECTED");
  return rebuilt;
}

function main(argv) {
  requireCondition(argv.length === 3, "FRESH_PRIMARY_ROLE_USAGE_REJECTED");
  process.stdout.write(`${JSON.stringify(prepareFreshPrimaryBootstrapRole({
    accountId: argv[0],
    sourceCommit: argv[1],
    treeDigest: argv[2]
  }), null, 2)}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) ===
  fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch (cause) {
    process.stderr.write(`${cause?.message ?? "FRESH_PRIMARY_ROLE_FAILED"}\n`);
    process.exitCode = 1;
  }
}

export const __test = Object.freeze({
  ROLE_NAME,
  STACK_NAME,
  TEMPLATE_PATH,
  TEMPLATE_SHA256,
  canonicalJson,
  digest,
  readReviewedTemplate
});
