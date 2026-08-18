#!/usr/bin/env node
import path from "node:path";
import { verifyReleaseControlMetadata } from "./control-plane-verification.js";

const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== "--root" || !path.isAbsolute(args[1])) {
  throw new Error("usage: verify-release-control-metadata.js --root /absolute/root");
}
const result = verifyReleaseControlMetadata({ rootDir: args[1] });
if (!result.ready) throw new Error("CONTROL_PLANE_METADATA_HOLD");
process.stdout.write(`${JSON.stringify({
  artifacts: result.artifacts,
  providerExecutionAuthorized: false,
  status: "VERIFIED"
})}\n`);
