import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import {
  parseAuthorityRaceArguments,
  runAuthorityRace
} from "../src/cloud/aws-authority-race.js";

function checkoutValue(args) {
  return execFileSync("git", args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"]
  }).trim();
}

export function assertExactCleanCheckout(sourceCommit) {
  if (
    checkoutValue(["rev-parse", "--show-toplevel"]) !==
      process.cwd() ||
    checkoutValue(["rev-parse", "--abbrev-ref", "HEAD"]) !== "main" ||
    checkoutValue(["rev-parse", "HEAD"]) !== sourceCommit ||
    checkoutValue(["status", "--porcelain=v1"]) !== "" ||
    checkoutValue(["rev-parse", "origin/main"]) !== sourceCommit ||
    !/^https:\/\/github\.com\/Flash-Bri\/tideproof(?:\.git)?$/.test(
      checkoutValue(["remote", "get-url", "origin"])
    )
  ) {
    throw new Error("AUTHORITY_RACE_CHECKOUT_REJECTED");
  }
}

async function invoke(functionArn, event) {
  const { InvokeCommand, LambdaClient } = await import(
    "@aws-sdk/client-lambda"
  );
  const { NodeHttpHandler } = await import(
    "@smithy/node-http-handler"
  );
  const client = new LambdaClient({
    region: "us-east-1",
    maxAttempts: 1,
    requestHandler: new NodeHttpHandler({
      connectionTimeout: 1_000,
      socketTimeout: 28_000
    })
  });
  return client.send(
    new InvokeCommand({
      FunctionName: functionArn,
      InvocationType: "RequestResponse",
      Payload: Buffer.from(JSON.stringify(event))
    })
  );
}

export async function main(argv = process.argv.slice(2)) {
  const options = parseAuthorityRaceArguments(argv);
  assertExactCleanCheckout(options.sourceCommit);
  const receipt = await runAuthorityRace({
    ...options,
    invoke
  });
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
        code: String(error?.message || "AUTHORITY_RACE_FAILED").slice(
          0,
          120
        )
      })}\n`
    );
    process.exitCode = 1;
  });
}
