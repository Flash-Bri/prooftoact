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
  if (!["--candidate", "--frozen-application-root", "--governance-evidence",
    "--npm-cli", "--provenance-evidence", "--root"]
    .includes(name) || typeof value !== "string" || !path.isAbsolute(value) ||
    values.has(name)) {
    throw new Error("usage: verify-control-plane-candidate.js --root /absolute/root --candidate /absolute/candidate.json [--governance-evidence /absolute/file] [--provenance-evidence /absolute/file --frozen-application-root /absolute/frozen-app --npm-cli /absolute/npm-cli.js] [--require-ready]");
  }
  values.set(name, value);
}
if (![values.get("--root"), values.get("--candidate")]
  .every((value) => path.isAbsolute(value ?? ""))) {
  throw new Error("CONTROL_PLANE_CANDIDATE_PATH_REJECTED");
}
const optionalJson = (name) => values.has(name)
  ? JSON.parse(fs.readFileSync(values.get(name), "utf8")) : null;
const provenanceArgumentCount = ["--provenance-evidence",
  "--frozen-application-root", "--npm-cli"].filter((name) =>
  values.has(name)).length;
if (![0, 3].includes(provenanceArgumentCount)) {
  throw new Error("CONTROL_PLANE_PROVENANCE_REPRODUCTION_ARGUMENT_REJECTED");
}
const candidate = JSON.parse(fs.readFileSync(values.get("--candidate"), "utf8"));
const result = verifyCandidate(candidate, {
  frozenApplicationRoot: values.get("--frozen-application-root") ?? null,
  governanceEvidence: optionalJson("--governance-evidence"),
  npmCli: values.get("--npm-cli") ?? null,
  provenanceEvidence: optionalJson("--provenance-evidence"),
  rootDir: values.get("--root")
});
if (requireReady && (result.localSourceReady !== true ||
  result.providerEvidenceReady !== true)) {
  throw new Error("CONTROL_PLANE_CANDIDATE_HOLD");
}
process.stdout.write(`${JSON.stringify(result)}\n`);
