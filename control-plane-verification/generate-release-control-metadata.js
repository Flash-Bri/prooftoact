#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { buildReleaseControlMetadata } from "./control-plane-verification.js";

const args = process.argv.slice(2);
if (args.length !== 6 || args[0] !== "--root" ||
  args[2] !== "--inventory-output" || args[4] !== "--notices-output" ||
  ![args[1], args[3], args[5]].every((value) => path.isAbsolute(value))) {
  throw new Error("usage: generate-release-control-metadata.js --root /absolute/root --inventory-output /absolute/DEPENDENCY_INVENTORY.json --notices-output /absolute/THIRD_PARTY_NOTICES.txt");
}
const metadata = buildReleaseControlMetadata({ rootDir: args[1] });
for (const [filePath, content] of [
  [args[3], metadata.dependencyInventory],
  [args[5], metadata.thirdPartyNotices]
]) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(filePath, content, { encoding: "utf8", flag: "wx", mode: 0o600 });
}
process.stdout.write(`${JSON.stringify({
  dependencyInventoryBytes: metadata.dependencyInventoryBytes,
  dependencyInventorySha256: metadata.dependencyInventorySha256,
  providerExecutionAuthorized: false,
  thirdPartyNoticesBytes: metadata.thirdPartyNoticesBytes,
  thirdPartyNoticesSha256: metadata.thirdPartyNoticesSha256
})}\n`);
