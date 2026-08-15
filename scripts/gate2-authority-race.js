import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  parseAuthorityDrillBinding,
  parseAuthorityRaceArguments,
  runAuthorityRace
} from "../src/cloud/aws-authority-race.js";
import {
  assertAwsSdkEvidenceEnvironment,
  explicitAwsCredentials,
  isolatedEvidenceProcessEnvironment,
  validateAwsEvidenceCaller
} from "../src/cloud/aws-evidence-identity.js";
import {
  assertIntegratedLiveDrillChildAuthorizationCurrent,
  authorizeIntegratedLiveDrillChildLaunch
} from "../src/cloud/integrated-live-drill-child-authorization.js";
import {
  assertCleanExactGitCheckout,
  assertExactGitRepositoryLayout,
  gitEnvironment,
  gitInvariantArguments,
  trustedGitExecutable
} from "./lib/exact-git-source.js";

const OFFICIAL_REMOTE =
  "https://github.com/Flash-Bri/prooftoact.git";

function exactRegularFileSha256(rootDir, relativePath) {
  const resolved = path.join(rootDir, relativePath);
  const stat = fs.lstatSync(resolved);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.nlink !== 1 ||
    fs.realpathSync(resolved) !== resolved
  ) {
    throw new Error("AUTHORITY_RACE_RELEASE_FILE_REJECTED");
  }
  return createHash("sha256")
    .update(fs.readFileSync(resolved))
    .digest("hex");
}

export function snapshotAuthorityRaceRelease(rootDir, checkout) {
  if (
    typeof rootDir !== "string" ||
    checkout?.sourceCommit === undefined ||
    checkout?.treeDigest === undefined
  ) {
    throw new Error("AUTHORITY_RACE_RELEASE_SNAPSHOT_REJECTED");
  }
  return Object.freeze({
    sourceCommit: checkout.sourceCommit,
    treeDigest: checkout.treeDigest,
    packageLockDigest: exactRegularFileSha256(rootDir, "package-lock.json"),
    dependencyInventoryDigest: exactRegularFileSha256(
      rootDir,
      "docs/DEPENDENCY_INVENTORY.md"
    )
  });
}

export function createAuthorityRaceGitRunner({
  rootDir = process.cwd(),
  sourceEnvironment = process.env,
  execute = execFileSync,
  gitExecutable = trustedGitExecutable()
} = {}) {
  const environment = gitEnvironment(
    isolatedEvidenceProcessEnvironment(sourceEnvironment)
  );
  return (args) => {
    if (
      !Array.isArray(args) ||
      args.length === 0 ||
      args.some(
        (value) =>
          typeof value !== "string" ||
          value.length === 0 ||
          /[\r\n\0]/.test(value)
      )
    ) {
      throw new Error("AUTHORITY_RACE_GIT_ARGUMENTS_REJECTED");
    }
    return execute(
      gitExecutable,
      [...gitInvariantArguments(), ...args],
      {
        cwd: rootDir,
        encoding: "utf8",
        env: environment,
        maxBuffer: 8 * 1024 * 1024,
        stdio: ["ignore", "pipe", "ignore"],
        timeout: 30_000
      }
    ).trim();
  };
}

export function fetchOfficialMain(
  readGit,
  {
    rootDir = process.cwd(),
    verifyRepositoryLayout = assertExactGitRepositoryLayout
  } = {}
) {
  verifyRepositoryLayout({ rootDir });
  readGit([
    "-c",
    "http.https://github.com/.extraheader=",
    "fetch",
    "--force",
    "--no-tags",
    "--no-recurse-submodules",
    OFFICIAL_REMOTE,
    "refs/heads/main:refs/remotes/origin/main"
  ]);
}

export function assertExactCleanCheckout(
  sourceCommit,
  {
    rootDir = process.cwd(),
    readGit = createAuthorityRaceGitRunner({ rootDir }),
    verifyCheckout = assertCleanExactGitCheckout,
    verifyRepositoryLayout = assertExactGitRepositoryLayout
  } = {}
) {
  if (!/^[0-9a-f]{40}$/.test(sourceCommit ?? "")) {
    throw new Error("AUTHORITY_RACE_CHECKOUT_REJECTED");
  }
  verifyRepositoryLayout({ rootDir });
  const treeDigest = readGit(["rev-parse", "HEAD^{tree}"]);
  const checkout = verifyCheckout({
    rootDir,
    sourceCommit,
    treeDigest
  });
  if (
    checkout.sourceCommit !== sourceCommit ||
    checkout.treeDigest !== treeDigest ||
    readGit(["symbolic-ref", "--short", "HEAD"]) !== "main" ||
    readGit(["rev-parse", "refs/remotes/origin/main"]) !== sourceCommit ||
    readGit(["remote", "get-url", "origin"]) !== OFFICIAL_REMOTE
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

export function authorityDrillBindingFromEnvironment(environment) {
  const raw = environment?.TIDEPROOF_AUTHORITY_DRILL_BINDING;
  if (
    typeof raw !== "string" ||
    raw.length === 0 ||
    raw.length > 4096 ||
    /[\0\r\n]/u.test(raw)
  ) {
    throw new Error("AUTHORITY_RACE_DRILL_BINDING_REJECTED");
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("AUTHORITY_RACE_DRILL_BINDING_REJECTED");
  }
  return parseAuthorityDrillBinding(parsed);
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

async function evidenceClients(credentials, childAuthorization) {
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
      assertIntegratedLiveDrillChildAuthorizationCurrent(childAuthorization);
      const identity = await sts.send(new GetCallerIdentityCommand({}));
      return {
        Account: identity.Account,
        Arn: identity.Arn,
        UserId: identity.UserId
      };
    },
    async authorityRoleResource() {
      assertIntegratedLiveDrillChildAuthorizationCurrent(childAuthorization);
      return cloudFormation.send(
        new DescribeStackResourceCommand({
          StackName: "prooftoact-gate2",
          LogicalResourceId: "AuthorityRaceCallerRole"
        })
      );
    },
    async invoke(functionArn, event) {
      assertIntegratedLiveDrillChildAuthorizationCurrent(childAuthorization);
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
  const childAuthorization = authorizeIntegratedLiveDrillChildLaunch(
    process.env,
    "AWS_AUTHORITY_RACE"
  );
  const options = parseAuthorityRaceArguments(argv);
  const drill = authorityDrillBindingFromEnvironment(process.env);
  if (drill.runId !== options.runId) {
    throw new Error("AUTHORITY_RACE_DRILL_BINDING_REJECTED");
  }
  const rootDir = process.cwd();
  const readGit = createAuthorityRaceGitRunner({ rootDir });
  fetchOfficialMain(readGit, { rootDir });
  const checkout = assertExactCleanCheckout(options.sourceCommit, {
    rootDir,
    readGit
  });
  const releaseSnapshot = snapshotAuthorityRaceRelease(rootDir, checkout);
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
  const clients = await evidenceClients(credentials, childAuthorization);
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
        authorityEvidenceBindingSha256:
          drill.authorityEvidenceBindingSha256,
        selectedEvidenceId: drill.selectedEvidenceId,
        selectedEvidenceDigest: drill.selectedEvidenceDigest,
        alphaProposalDigest: drill.alphaProposalDigest,
        bravoProposalDigest: drill.bravoProposalDigest,
        alphaLogicalActionDigest: drill.alphaLogicalActionDigest,
        bravoLogicalActionDigest: drill.bravoLogicalActionDigest,
        packageLockDigest: releaseSnapshot.packageLockDigest,
        dependencyInventoryDigest:
          releaseSnapshot.dependencyInventoryDigest
      }
    }
  );
  const raceReceipt = await runAuthorityRace({
    ...options,
    drill,
    callerBinding,
    invoke: clients.invoke
  });
  assertIntegratedLiveDrillChildAuthorizationCurrent(childAuthorization);
  const receipt = {
    ...raceReceipt,
    providerOperations: {
      cloudFormationDescribeStackResourceRequests: 1,
      lambdaInvokeRequests: 5,
      stsGetCallerIdentityRequests: 1
    }
  };
  if (receipt.treeDigest !== checkout.treeDigest) {
    throw new Error("AUTHORITY_RACE_TREE_BINDING_REJECTED");
  }
  fetchOfficialMain(readGit, { rootDir });
  const finalCheckout = assertExactCleanCheckout(options.sourceCommit, {
    rootDir,
    readGit
  });
  const finalReleaseSnapshot = snapshotAuthorityRaceRelease(
    rootDir,
    finalCheckout
  );
  if (
    finalCheckout.treeDigest !== checkout.treeDigest ||
    finalReleaseSnapshot.sourceCommit !== releaseSnapshot.sourceCommit ||
    finalReleaseSnapshot.treeDigest !== releaseSnapshot.treeDigest ||
    finalReleaseSnapshot.packageLockDigest !==
      releaseSnapshot.packageLockDigest ||
    finalReleaseSnapshot.dependencyInventoryDigest !==
      releaseSnapshot.dependencyInventoryDigest
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

export const __test = Object.freeze({
  OFFICIAL_REMOTE,
  fetchOfficialMain
});
