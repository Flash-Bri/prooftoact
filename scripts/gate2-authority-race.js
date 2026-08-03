import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { pathToFileURL } from "node:url";
import {
  parseAuthorityRaceArguments,
  runAuthorityRace
} from "../src/cloud/aws-authority-race.js";
import {
  assertAwsSdkEvidenceEnvironment,
  explicitAwsCredentials,
  isolatedEvidenceProcessEnvironment,
  validateAwsEvidenceCaller
} from "../src/cloud/aws-evidence-identity.js";
import { runReleaseProvenance } from "./verify-release-provenance.js";

function checkoutValue(args) {
  return execFileSync("git", ["-c", "core.fsmonitor=false", ...args], {
    encoding: "utf8",
    env: {
      ...isolatedEvidenceProcessEnvironment(process.env),
      GIT_NO_REPLACE_OBJECTS: "1"
    },
    stdio: ["ignore", "pipe", "ignore"]
  }).trim();
}

function checkoutOptionalValue(args) {
  try {
    return checkoutValue(args);
  } catch {
    return "";
  }
}

function fetchOfficialMain() {
  checkoutValue([
    "fetch",
    "--force",
    "--no-tags",
    "origin",
    "refs/heads/main:refs/remotes/origin/main"
  ]);
}

export function assertExactCleanCheckout(sourceCommit) {
  const graftsPath = checkoutValue(["rev-parse", "--git-path", "info/grafts"]);
  const alternatesPath = checkoutValue([
    "rev-parse",
    "--git-path",
    "objects/info/alternates"
  ]);
  const treeDigest = checkoutValue(["rev-parse", "HEAD^{tree}"]);
  const assumeUnchanged = checkoutValue(["ls-files", "-v"])
    .split("\n")
    .filter(Boolean)
    .some((line) => /^[a-z]/u.test(line));
  const skipWorktree = checkoutValue(["ls-files", "-t"])
    .split("\n")
    .filter(Boolean)
    .some((line) => line.startsWith("S "));
  const sparseCheckoutPath = checkoutValue([
    "rev-parse",
    "--git-path",
    "info/sparse-checkout"
  ]);
  if (
    checkoutValue(["rev-parse", "--show-toplevel"]) !==
      process.cwd() ||
    checkoutValue(["rev-parse", "--abbrev-ref", "HEAD"]) !== "main" ||
    checkoutValue(["rev-parse", "HEAD"]) !== sourceCommit ||
    checkoutValue(["status", "--porcelain=v1"]) !== "" ||
    checkoutValue(["rev-parse", "origin/main"]) !== sourceCommit ||
    checkoutValue(["replace", "-l"]) !== "" ||
    existsSync(graftsPath) ||
    existsSync(alternatesPath) ||
    existsSync(sparseCheckoutPath) ||
    checkoutOptionalValue(["config", "--get", "core.sparseCheckout"]) !== "" ||
    assumeUnchanged ||
    skipWorktree ||
    !/^[0-9a-f]{40}$/.test(treeDigest) ||
    checkoutValue(["rev-parse", "--is-shallow-repository"]) !== "false" ||
    !/^https:\/\/github\.com\/Flash-Bri\/prooftoact(?:\.git)?$/.test(
      checkoutValue(["remote", "get-url", "origin"])
    )
  ) {
    throw new Error("AUTHORITY_RACE_CHECKOUT_REJECTED");
  }
  return Object.freeze({ sourceCommit, treeDigest });
}

export function validateAuthorityRaceExpectedPrincipal(
  expectedAccountId,
  expectedPrincipalArn
) {
  if (
    !/^\d{12}$/.test(expectedAccountId ?? "") ||
    typeof expectedPrincipalArn !== "string" ||
    !new RegExp(
      `^arn:aws:iam::${expectedAccountId}:role/` +
        "prooftoact-gate2-AuthorityRaceCallerRole-[A-Za-z0-9]+$"
    ).test(expectedPrincipalArn)
  ) {
    throw new Error("AUTHORITY_RACE_EXPECTED_ROLE_REJECTED");
  }
  return expectedPrincipalArn;
}

export function authorityPrincipalFromStackResource(
  expectedAccountId,
  response
) {
  const detail = response?.StackResourceDetail;
  const physicalRoleName = detail?.PhysicalResourceId;
  const stackIdPattern = new RegExp(
    `^arn:aws:cloudformation:us-east-1:${expectedAccountId}:` +
      "stack/prooftoact-gate2/[0-9a-f-]{36}$"
  );
  if (
    !/^\d{12}$/.test(expectedAccountId ?? "") ||
    detail?.StackName !== "prooftoact-gate2" ||
    detail?.LogicalResourceId !== "AuthorityRaceCallerRole" ||
    detail?.ResourceType !== "AWS::IAM::Role" ||
    !["CREATE_COMPLETE", "UPDATE_COMPLETE"].includes(
      detail?.ResourceStatus
    ) ||
    !stackIdPattern.test(detail?.StackId ?? "") ||
    !/^prooftoact-gate2-AuthorityRaceCallerRole-[A-Za-z0-9]+$/.test(
      physicalRoleName ?? ""
    )
  ) {
    throw new Error("AUTHORITY_RACE_STACK_ROLE_REJECTED");
  }
  return validateAuthorityRaceExpectedPrincipal(
    expectedAccountId,
    `arn:aws:iam::${expectedAccountId}:role/${physicalRoleName}`
  );
}

export function safeAuthorityRaceFailureCode(error) {
  const candidate = String(error?.message ?? "");
  return /^(?:AUTHORITY_RACE|AWS_EVIDENCE)_[A-Z0-9_]{1,100}$/.test(
    candidate
  )
    ? candidate
    : "AUTHORITY_RACE_UNKNOWN";
}

export function awsEvidenceClientOptions(credentials, requestHandler) {
  return {
    region: "us-east-1",
    credentials,
    ignoreConfiguredEndpointUrls: true,
    maxAttempts: 1,
    requestHandler
  };
}

async function evidenceClients(credentials) {
  const {
    CloudFormationClient,
    DescribeStackResourceCommand
  } = await import("@aws-sdk/client-cloudformation");
  const { InvokeCommand, LambdaClient } = await import(
    "@aws-sdk/client-lambda"
  );
  const { GetCallerIdentityCommand, STSClient } = await import(
    "@aws-sdk/client-sts"
  );
  const { NodeHttpHandler } = await import(
    "@smithy/node-http-handler"
  );
  const requestHandler = new NodeHttpHandler({
    connectionTimeout: 1_000,
    socketTimeout: 28_000
  });
  const clientOptions = awsEvidenceClientOptions(
    credentials,
    requestHandler
  );
  const lambda = new LambdaClient(clientOptions);
  const sts = new STSClient(clientOptions);
  const cloudFormation = new CloudFormationClient(clientOptions);
  return {
    async callerIdentity() {
      const identity = await sts.send(new GetCallerIdentityCommand({}));
      return {
        Account: identity.Account,
        Arn: identity.Arn,
        UserId: identity.UserId
      };
    },
    async authorityRoleResource() {
      return cloudFormation.send(
        new DescribeStackResourceCommand({
          StackName: "prooftoact-gate2",
          LogicalResourceId: "AuthorityRaceCallerRole"
        })
      );
    },
    async invoke(functionArn, event) {
      return lambda.send(
        new InvokeCommand({
          FunctionName: functionArn,
          InvocationType: "RequestResponse",
          Payload: Buffer.from(JSON.stringify(event))
        })
      );
    }
  };
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseAuthorityRaceArguments(argv);
  fetchOfficialMain();
  const checkout = assertExactCleanCheckout(options.sourceCommit);
  const provenance = await runReleaseProvenance();
  if (
    provenance.source.commit !== checkout.sourceCommit ||
    provenance.source.tree !== checkout.treeDigest
  ) {
    throw new Error("AUTHORITY_RACE_PROVENANCE_REJECTED");
  }
  assertAwsSdkEvidenceEnvironment(process.env);
  const credentials = explicitAwsCredentials(process.env, {
    requireSessionToken: true
  });
  const expectedAccountId =
    process.env.AWS_EVIDENCE_EXPECTED_ACCOUNT_ID;
  const expectedCallerArn =
    process.env.AWS_EVIDENCE_EXPECTED_AUTHORITY_CALLER_ARN;
  const expectedCallerUserId =
    process.env.AWS_EVIDENCE_EXPECTED_AUTHORITY_CALLER_USER_ID;
  const functionAccount =
    /^arn:aws:lambda:us-east-1:(\d{12}):/.exec(
      options.functionArn
    )?.[1];
  if (
    !/^\d{12}$/.test(expectedAccountId ?? "") ||
    functionAccount !== expectedAccountId
  ) {
    throw new Error("AUTHORITY_RACE_EXPECTED_ACCOUNT_REJECTED");
  }
  const clients = await evidenceClients(credentials);
  const expectedPrincipalArn = authorityPrincipalFromStackResource(
    expectedAccountId,
    await clients.authorityRoleResource()
  );
  const callerBinding = validateAwsEvidenceCaller(
    await clients.callerIdentity(),
    {
      expectedAccountId,
      expectedPrincipalArn,
      expectedCallerArn,
      expectedCallerUserId,
      bindingContext: {
        purpose: "gate2-authority-race",
        sourceCommit: options.sourceCommit,
        configDigest: options.configDigest,
        raceId: options.raceId,
        runId: options.runId,
        functionArn: options.functionArn,
        packageLockDigest:
          provenance.dependencies.installedTree.packageLockSha256,
        dependencyInventoryDigest:
          provenance.dependencies.inventory.inventorySha256
      }
    }
  );
  const receipt = await runAuthorityRace({
    ...options,
    callerBinding,
    invoke: clients.invoke
  });
  if (receipt.treeDigest !== checkout.treeDigest) {
    throw new Error("AUTHORITY_RACE_TREE_BINDING_REJECTED");
  }
  fetchOfficialMain();
  const finalCheckout = assertExactCleanCheckout(options.sourceCommit);
  const finalProvenance = await runReleaseProvenance();
  if (
    finalCheckout.treeDigest !== checkout.treeDigest ||
    finalProvenance.source.commit !== provenance.source.commit ||
    finalProvenance.source.tree !== provenance.source.tree ||
    finalProvenance.dependencies.installedTree.packageLockSha256 !==
      provenance.dependencies.installedTree.packageLockSha256 ||
    finalProvenance.dependencies.inventory.inventorySha256 !==
      provenance.dependencies.inventory.inventorySha256
  ) {
    throw new Error("AUTHORITY_RACE_POST_EVIDENCE_DRIFT");
  }
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
}

const startedDirectly =
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  main().catch((error) => {
    process.stderr.write(
      `${JSON.stringify({
        schemaVersion: "tideproof.aws-authority-race-error.v1",
        status: "FAIL",
        code: safeAuthorityRaceFailureCode(error)
      })}\n`
    );
    process.exitCode = 1;
  });
}
