import fs from "node:fs";
import path from "node:path";
import {
  deploymentConfigDigest
} from "../src/cloud/aws-gate2-template.js";

const manifestPath = process.argv[2];
if (!manifestPath || process.argv.length !== 3) {
  throw new Error(
    "USAGE: node scripts/gate2-config-digest.js <nonsecret-manifest.json>"
  );
}

const resolvedPath = path.resolve(process.cwd(), manifestPath);
const raw = fs.readFileSync(resolvedPath, "utf8");
const configuration = JSON.parse(raw);
const configDigest = deploymentConfigDigest(configuration);

process.stdout.write(
  `${JSON.stringify(
    {
      schemaVersion: "tideproof.gate2-config-digest.v1",
      manifestPath: path.relative(process.cwd(), resolvedPath),
      configDigest
    },
    null,
    2
  )}\n`
);
