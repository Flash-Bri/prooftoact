#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

import { publishOrReadExactOwnedFile } from
  "../src/cloud/atomic-create-only-file.js";
import {
  canonicalProvenanceJson,
  generateControlPlaneProvenanceEvidence
} from "./control-plane-provenance.js";

function parse(args) {
  const values = new Map();
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (!["--application-root", "--control-root", "--npm-cli", "--output"]
      .includes(name) || typeof value !== "string" || !path.isAbsolute(value) ||
      values.has(name)) {
      throw new Error("CONTROL_PLANE_PROVENANCE_ARGUMENT_REJECTED");
    }
    values.set(name, value);
  }
  if (values.size !== 4) {
    throw new Error("usage: generate-control-plane-provenance-evidence.js --control-root /absolute/control --application-root /absolute/frozen-app --npm-cli /absolute/npm-cli.js --output /absolute/evidence.json");
  }
  return values;
}

function assertOutputRoot(root) {
  const stat = fs.lstatSync(root);
  if (fs.realpathSync(root) !== root || !stat.isDirectory() ||
    stat.isSymbolicLink() || stat.uid !== process.getuid() ||
    (stat.mode & 0o077) !== 0) {
    throw new Error("CONTROL_PLANE_PROVENANCE_OUTPUT_ROOT_REJECTED");
  }
}

function assertExternalPath(filePath, checkoutRoots) {
  const outputRoot = fs.realpathSync(path.dirname(filePath));
  const exactPath = path.join(outputRoot, path.basename(filePath));
  if (exactPath !== filePath) {
    throw new Error("CONTROL_PLANE_PROVENANCE_OUTPUT_PATH_REJECTED");
  }
  const outputStat = fs.lstatSync(outputRoot);
  for (const checkoutRoot of checkoutRoots) {
    const root = fs.realpathSync(checkoutRoot);
    const rootStat = fs.lstatSync(root);
    const relative = path.relative(root, exactPath);
    const outside = relative === ".." || relative.startsWith(`..${path.sep}`);
    if (!outside || (rootStat.dev === outputStat.dev &&
      rootStat.ino === outputStat.ino)) {
      throw new Error("CONTROL_PLANE_PROVENANCE_OUTPUT_PATH_REJECTED");
    }
  }
}

const values = parse(process.argv.slice(2));
const output = path.resolve(values.get("--output"));
const outputRoot = path.dirname(output);
assertOutputRoot(outputRoot);
assertExternalPath(output, [values.get("--control-root"),
  values.get("--application-root")]);
const evidence = generateControlPlaneProvenanceEvidence({
  controlPlaneRoot: values.get("--control-root"),
  frozenApplicationRoot: values.get("--application-root"),
  npmCli: values.get("--npm-cli")
});
const publication = publishOrReadExactOwnedFile({
  assertRoot: () => assertOutputRoot(outputRoot),
  bytes: Buffer.from(`${canonicalProvenanceJson(evidence)}\n`, "utf8"),
  code: "CONTROL_PLANE_PROVENANCE_PUBLICATION_REJECTED",
  filePath: output,
  maximumBytes: 16 * 1024 * 1024,
  mode: 0o600,
  rootPath: outputRoot
});
process.stdout.write(`${JSON.stringify({
  bodySha256: evidence.bodySha256,
  created: publication.created,
  output,
  providerExecutionAuthorized: false,
  status: evidence.body.decision.status
})}\n`);
