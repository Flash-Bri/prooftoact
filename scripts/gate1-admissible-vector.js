import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";

import { AdmissibleVectorRetriever } from "../src/cloud/admissible-vector-retrieval.js";
import { isolatedEvidenceProcessEnvironment } from "../src/cloud/aws-evidence-identity.js";

function requiredEnvironment(name) {
  const value = process.env[name];
  if (typeof value !== "string" || value === "") {
    throw new Error(`ADMISSIBLE_VECTOR_${name}_REQUIRED`);
  }
  return value;
}

function gitValue(args) {
  return execFileSync("git", args, {
    encoding: "utf8",
    env: isolatedEvidenceProcessEnvironment(process.env),
    stdio: ["ignore", "pipe", "ignore"]
  }).trim();
}

export function safeAdmissibleVectorFailureCode(error) {
  const candidate = String(error?.message ?? "");
  return /^ADMISSIBLE_VECTOR_[A-Z0-9_]{1,100}$/.test(candidate)
    ? candidate
    : "ADMISSIBLE_VECTOR_UNKNOWN";
}

export async function main() {
  const sourceCommit = gitValue(["rev-parse", "HEAD"]);
  const treeDigest = gitValue(["rev-parse", "HEAD^{tree}"]);
  if (gitValue(["status", "--porcelain=v1"]) !== "") {
    throw new Error("ADMISSIBLE_VECTOR_WORKTREE_DIRTY");
  }
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

const startedDirectly =
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  main().catch((error) => {
    process.stderr.write(`${safeAdmissibleVectorFailureCode(error)}\n`);
    process.exitCode = 1;
  });
}
