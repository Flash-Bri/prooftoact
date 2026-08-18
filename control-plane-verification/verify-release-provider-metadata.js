#!/usr/bin/env node
import path from "node:path";
import { verifyReleaseProviderMetadata } from "./control-plane-verification.js";

const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== "--root" || !path.isAbsolute(args[1])) {
  throw new Error("usage: verify-release-provider-metadata.js --root /absolute/root");
}
const result = verifyReleaseProviderMetadata({ rootDir: args[1] });
if (!result.ready) throw new Error("RELEASE_PROVIDER_METADATA_HOLD");
process.stdout.write(`${JSON.stringify({
  artifacts: result.artifacts,
  packageCount: result.dependencies.packageCount,
  providerExecutionAuthorized: false,
  runtimeSetSha256: result.dependencies.runtimeSetSha256,
  status: "VERIFIED"
})}\n`);
