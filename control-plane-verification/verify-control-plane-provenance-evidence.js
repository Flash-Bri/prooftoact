#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

import {
  verifyControlPlaneProvenanceEvidence
} from "./control-plane-provenance.js";

function parse(args) {
  const values = new Map();
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (!["--application-root", "--control-root", "--evidence", "--npm-cli"]
      .includes(name) || typeof value !== "string" || !path.isAbsolute(value) ||
      values.has(name)) {
      throw new Error("CONTROL_PLANE_PROVENANCE_ARGUMENT_REJECTED");
    }
    values.set(name, value);
  }
  if (values.size !== 4) {
    throw new Error("usage: verify-control-plane-provenance-evidence.js --control-root /absolute/control --application-root /absolute/frozen-app --npm-cli /absolute/npm-cli.js --evidence /absolute/evidence.json");
  }
  return values;
}

function readEvidence(filePath) {
  const descriptor = fs.openSync(filePath,
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(descriptor);
    const named = fs.lstatSync(filePath);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size <= 0 ||
      stat.size > 16 * 1024 * 1024 || stat.uid !== process.getuid() ||
      (stat.mode & 0o077) !== 0 || !named.isFile() ||
      named.isSymbolicLink() || named.dev !== stat.dev || named.ino !== stat.ino ||
      fs.realpathSync(filePath) !== filePath) {
      throw new Error("CONTROL_PLANE_PROVENANCE_EVIDENCE_FILE_REJECTED");
    }
    const bytes = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(descriptor, bytes, offset,
        bytes.length - offset, offset);
      if (count <= 0) {
        throw new Error("CONTROL_PLANE_PROVENANCE_EVIDENCE_FILE_REJECTED");
      }
      offset += count;
    }
    const after = fs.fstatSync(descriptor);
    const afterNamed = fs.lstatSync(filePath);
    if (after.dev !== stat.dev || after.ino !== stat.ino ||
      after.size !== stat.size || afterNamed.dev !== stat.dev ||
      afterNamed.ino !== stat.ino) {
      throw new Error("CONTROL_PLANE_PROVENANCE_EVIDENCE_FILE_REJECTED");
    }
    return JSON.parse(bytes.toString("utf8"));
  } finally {
    fs.closeSync(descriptor);
  }
}

function assertExternalEvidence(filePath, checkoutRoots) {
  const exactPath = fs.realpathSync(filePath);
  if (exactPath !== filePath) {
    throw new Error("CONTROL_PLANE_PROVENANCE_EVIDENCE_PATH_REJECTED");
  }
  const evidenceStat = fs.lstatSync(exactPath);
  for (const checkoutRoot of checkoutRoots) {
    const root = fs.realpathSync(checkoutRoot);
    const rootStat = fs.lstatSync(root);
    const relative = path.relative(root, exactPath);
    const outside = relative === ".." || relative.startsWith(`..${path.sep}`);
    if (!outside || (rootStat.dev === evidenceStat.dev &&
      rootStat.ino === evidenceStat.ino)) {
      throw new Error("CONTROL_PLANE_PROVENANCE_EVIDENCE_PATH_REJECTED");
    }
  }
}

const values = parse(process.argv.slice(2));
assertExternalEvidence(values.get("--evidence"), [values.get("--control-root"),
  values.get("--application-root")]);
const result = verifyControlPlaneProvenanceEvidence(
  readEvidence(values.get("--evidence")),
  {
    controlPlaneRoot: values.get("--control-root"),
    frozenApplicationRoot: values.get("--application-root"),
    npmCli: values.get("--npm-cli")
  }
);
process.stdout.write(`${JSON.stringify(result)}\n`);
