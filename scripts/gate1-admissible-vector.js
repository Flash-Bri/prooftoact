import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { Pool } from "pg";

import {
  AdmissibleVectorRetriever,
  admissibleVectorAuditorPoolConfig,
  admissibleVectorPoolConfig,
  proveAdmissibleVectorSnapshot
} from "../src/cloud/admissible-vector-retrieval.js";
import { isolatedEvidenceProcessEnvironment } from "../src/cloud/aws-evidence-identity.js";
import {
  assertExactGitRepositoryLayout,
  gitEnvironment,
  gitInvariantArguments,
  trustedGitExecutable
} from "./lib/exact-git-source.js";

const OFFICIAL_REMOTE = "https://github.com/Flash-Bri/prooftoact.git";

function requiredEnvironment(name) {
  const value = process.env[name];
  if (typeof value !== "string" || value === "") {
    throw new Error(`ADMISSIBLE_VECTOR_${name}_REQUIRED`);
  }
  return value;
}

function gitOutput(args) {
  return execFileSync(
    trustedGitExecutable(),
    [...gitInvariantArguments(), ...args],
    {
      encoding: "utf8",
      env: gitEnvironment(
        isolatedEvidenceProcessEnvironment(process.env)
      ),
      maxBuffer: 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 30_000
    }
  );
}

function gitValue(args) {
  return gitOutput(args).trim();
}

function cleanIndexFlags() {
  const output = gitOutput(["ls-files", "-v", "-z", "--cached"]);
  return (
    output.endsWith("\0") &&
    output
      .slice(0, -1)
      .split("\0")
      .every((record) => record.startsWith("H "))
  );
}

function sourceBinding({ officialMain = false } = {}) {
  assertExactGitRepositoryLayout({ rootDir: process.cwd() });
  const sourceCommit = gitValue(["rev-parse", "HEAD"]);
  const treeDigest = gitValue(["rev-parse", "HEAD^{tree}"]);
  if (gitValue(["replace", "--list"]) !== "") {
    throw new Error("ADMISSIBLE_VECTOR_GIT_REPLACEMENT_REJECTED");
  }
  if (!cleanIndexFlags()) {
    throw new Error("ADMISSIBLE_VECTOR_GIT_INDEX_FLAGS_REJECTED");
  }
  if (
    gitValue([
      "-c",
      "core.fsmonitor=false",
      "status",
      "--porcelain=v1",
      "--untracked-files=all"
    ]) !== ""
  ) {
    throw new Error("ADMISSIBLE_VECTOR_WORKTREE_DIRTY");
  }
  if (!officialMain) {
    return { sourceCommit, treeDigest };
  }
  const remote = gitValue(["remote", "get-url", "origin"]);
  if (
    remote !== OFFICIAL_REMOTE &&
    remote !== OFFICIAL_REMOTE.slice(0, -4)
  ) {
    throw new Error("ADMISSIBLE_VECTOR_OFFICIAL_REMOTE_REQUIRED");
  }
  gitValue([
    "-c",
    "http.https://github.com/.extraheader=",
    "fetch",
    "--force",
    "--quiet",
    "--no-tags",
    "--no-recurse-submodules",
    OFFICIAL_REMOTE,
    "refs/heads/main:refs/remotes/origin/main"
  ]);
  if (gitValue(["replace", "--list"]) !== "") {
    throw new Error("ADMISSIBLE_VECTOR_GIT_REPLACEMENT_REJECTED");
  }
  if (!cleanIndexFlags()) {
    throw new Error("ADMISSIBLE_VECTOR_GIT_INDEX_FLAGS_REJECTED");
  }
  if (
    gitValue(["symbolic-ref", "--short", "HEAD"]) !== "main" ||
    gitValue(["rev-parse", "refs/remotes/origin/main"]) !== sourceCommit ||
    gitValue(["rev-parse", "HEAD"]) !== sourceCommit ||
    gitValue(["rev-parse", "HEAD^{tree}"]) !== treeDigest ||
    gitValue([
      "-c",
      "core.fsmonitor=false",
      "status",
      "--porcelain=v1",
      "--untracked-files=all"
    ]) !== ""
  ) {
    throw new Error("ADMISSIBLE_VECTOR_OFFICIAL_MAIN_REQUIRED");
  }
  return { sourceCommit, treeDigest };
}

function proofSpec() {
  try {
    return JSON.parse(
      requiredEnvironment("TIDEPROOF_ADMISSIBLE_VECTOR_PROOF_SPEC")
    );
  } catch (error) {
    if (
      error?.message ===
      "ADMISSIBLE_VECTOR_TIDEPROOF_ADMISSIBLE_VECTOR_PROOF_SPEC_REQUIRED"
    ) {
      throw error;
    }
    throw new Error("ADMISSIBLE_VECTOR_PROOF_SPEC_JSON");
  }
}

export function safeAdmissibleVectorFailureCode(error) {
  const candidate = String(error?.message ?? "");
  return /^ADMISSIBLE_VECTOR_[A-Z0-9_]{1,100}$/.test(candidate)
    ? candidate
    : "ADMISSIBLE_VECTOR_UNKNOWN";
}

export async function runAdmissibleVector() {
  const { sourceCommit, treeDigest } = sourceBinding();
  const queryEmbedding = JSON.parse(
    requiredEnvironment("TIDEPROOF_QUERY_EMBEDDING")
  );
  const retriever = new AdmissibleVectorRetriever({
    connectionString: requiredEnvironment("DATABASE_URL")
  });
  try {
    const result = await retriever.retrieve({
      tenantId: requiredEnvironment("TIDEPROOF_TENANT_ID"),
      retrievalId: requiredEnvironment("TIDEPROOF_RETRIEVAL_ID"),
      incidentId: requiredEnvironment("TIDEPROOF_INCIDENT_ID"),
      agency: requiredEnvironment("TIDEPROOF_AGENCY"),
      queryEmbedding,
      limit: Number(process.env.TIDEPROOF_VECTOR_LIMIT ?? 10),
      ttlMs: Number(process.env.TIDEPROOF_VECTOR_TTL_MS ?? 60_000)
    });
    process.stdout.write(
      `${JSON.stringify(
        {
          schemaVersion: "tideproof.gate1.admissible-vector-run.v1",
          status: "PASS",
          sourceCommit,
          treeDigest,
          result,
          claimBoundary:
            "This executes the integrated short-lived admissibility-snapshot ranking path and verifies cleanup. It is not an accepted DVI plan/exclusion receipt, an authorization result, or a production-suitability claim."
        },
        null,
        2
      )}\n`
    );
  } finally {
    await retriever.close();
  }
}

export async function runAdmissibleVectorProof() {
  const { sourceCommit, treeDigest } = sourceBinding({
    officialMain: true
  });
  const environment = isolatedEvidenceProcessEnvironment(process.env);
  const authorizerConfig = admissibleVectorPoolConfig(
    requiredEnvironment("DATABASE_URL"),
    environment
  );
  const auditorConfig = admissibleVectorAuditorPoolConfig(
    requiredEnvironment("TIDEPROOF_AUDITOR_DATABASE_URL"),
    environment
  );
  const authorizerPool = new Pool(authorizerConfig);
  const auditorPool = new Pool(auditorConfig);
  let receipt;
  let primaryError = null;
  try {
    receipt = await proveAdmissibleVectorSnapshot({
      authorizerPool,
      auditorPool,
      spec: proofSpec(),
      sourceCommit,
      treeDigest
    });
  } catch (error) {
    primaryError = error;
  }
  const closeResults = await Promise.allSettled([
    authorizerPool.end(),
    auditorPool.end()
  ]);
  const closeError = closeResults.some(({ status }) => status === "rejected")
    ? new Error("ADMISSIBLE_VECTOR_POOL_CLOSE_FAILED")
    : null;
  if (primaryError && closeError) {
    throw new AggregateError(
      [primaryError, closeError],
      "ADMISSIBLE_VECTOR_OPERATION_AND_POOL_CLOSE_FAILED"
    );
  }
  if (primaryError) {
    throw primaryError;
  }
  if (closeError) {
    throw closeError;
  }
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
}

export async function main(args = process.argv.slice(2)) {
  if (args.length === 0) {
    return runAdmissibleVector();
  }
  if (args.length === 1 && args[0] === "--proof") {
    return runAdmissibleVectorProof();
  }
  throw new Error("ADMISSIBLE_VECTOR_ARGUMENTS_REJECTED");
}

const startedDirectly =
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  main().catch((error) => {
    process.stderr.write(`${safeAdmissibleVectorFailureCode(error)}\n`);
    process.exitCode = 1;
  });
}
