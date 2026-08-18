#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { buildCandidate, canonicalJson } from "./control-plane-verification.js";

function parse(args) {
  const values = new Map();
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (!["--governance-evidence", "--output", "--provenance-evidence", "--root"]
      .includes(name) || typeof value !== "string") {
      throw new Error("usage: generate-control-plane-candidate.js --root /absolute/root --output /absolute/candidate.json [--governance-evidence /absolute/file] [--provenance-evidence /absolute/file]");
    }
    values.set(name, value);
  }
  if (![values.get("--root"), values.get("--output")]
    .every((value) => path.isAbsolute(value ?? ""))) {
    throw new Error("CONTROL_PLANE_CANDIDATE_PATH_REJECTED");
  }
  return values;
}

function optionalJson(filePath) {
  if (filePath === undefined) return null;
  if (!path.isAbsolute(filePath)) throw new Error("CONTROL_PLANE_EVIDENCE_PATH_REJECTED");
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

const args = parse(process.argv.slice(2));
const candidate = buildCandidate({
  governanceEvidence: optionalJson(args.get("--governance-evidence")),
  provenanceEvidence: optionalJson(args.get("--provenance-evidence")),
  rootDir: args.get("--root")
});
const output = args.get("--output");
fs.mkdirSync(path.dirname(output), { recursive: true, mode: 0o700 });
fs.writeFileSync(output, `${canonicalJson(candidate)}\n`, {
  encoding: "utf8",
  flag: "wx",
  mode: 0o600
});
process.stdout.write(`${JSON.stringify({
  bodySha256: candidate.bodySha256,
  localSourceReady: candidate.body.readiness.localSourceReady,
  output,
  providerEvidenceReady: candidate.body.readiness.providerEvidenceReady,
  providerExecutionAuthorized: false,
  status: candidate.body.readiness.finalDisposition
})}\n`);
