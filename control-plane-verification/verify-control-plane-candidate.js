#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { verifyCandidate } from "./control-plane-verification.js";

const args = process.argv.slice(2);
const requireReadyIndex = args.indexOf("--require-ready");
const requireReady = requireReadyIndex !== -1;
if (requireReady) args.splice(requireReadyIndex, 1);
const values = new Map();
for (let index = 0; index < args.length; index += 2) {
  const name = args[index];
  const value = args[index + 1];
  if (!["--candidate", "--governance-evidence", "--provenance-evidence", "--root"]
    .includes(name) || typeof value !== "string" || !path.isAbsolute(value)) {
    throw new Error("usage: verify-control-plane-candidate.js --root /absolute/root --candidate /absolute/candidate.json [--governance-evidence /absolute/file] [--provenance-evidence /absolute/file] [--require-ready]");
  }
  values.set(name, value);
}
if (![values.get("--root"), values.get("--candidate")]
  .every((value) => path.isAbsolute(value ?? ""))) {
  throw new Error("CONTROL_PLANE_CANDIDATE_PATH_REJECTED");
}
const optionalJson = (name) => values.has(name)
  ? JSON.parse(fs.readFileSync(values.get(name), "utf8")) : null;
const candidate = JSON.parse(fs.readFileSync(values.get("--candidate"), "utf8"));
const result = verifyCandidate(candidate, {
  governanceEvidence: optionalJson("--governance-evidence"),
  provenanceEvidence: optionalJson("--provenance-evidence"),
  rootDir: values.get("--root")
});
if (requireReady && (result.localSourceReady !== true ||
  result.providerEvidenceReady !== true)) {
  throw new Error("CONTROL_PLANE_CANDIDATE_HOLD");
}
process.stdout.write(`${JSON.stringify(result)}\n`);
