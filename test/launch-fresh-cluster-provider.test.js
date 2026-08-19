import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { __test } from "../scripts/launch-fresh-cluster-provider.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const LAUNCHER = fs.readFileSync(path.join(
  ROOT, "scripts/launch-fresh-cluster-provider.js"
), "utf8");
const WORKFLOW = fs.readFileSync(path.join(
  ROOT, ".github/workflows/prooftoact-sealed-fresh-primary.yml"
), "utf8");

function args() {
  return __test.EXPECTED_ARGUMENTS.flatMap((name, index) => [
    name,
    name === "--approval-sha256"
      ? "c".repeat(64)
      : name === "--caller-workflow-ref"
        ? "Flash-Bri/prooftoact/.github/workflows/" +
          "prooftoact-fresh-primary.yml@refs/heads/main"
        : name === "--caller-workflow-sha"
          ? "d".repeat(40)
          : name === "--expected-commit"
      ? "a".repeat(40)
      : name === "--expected-tree"
        ? "b".repeat(40)
        : name === "--human-authorization-signer-sha256"
          ? "c".repeat(64)
        : String(index + 1)
  ]);
}

test("launcher itself statically imports built-ins only", () => {
  const specifiers = [...LAUNCHER.matchAll(
    /^import(?:[\s\S]*?\sfrom\s+|\s+)["']([^"']+)["'];$/gmu
  )].map((match) => match[1]).sort();
  assert.deepEqual(specifiers, [
    "node:child_process",
    "node:crypto",
    "node:fs",
    "node:path",
    "node:url"
  ]);
  assert.doesNotMatch(LAUNCHER, /^import .* from "pg";/mu);
  assert.doesNotMatch(LAUNCHER, /^import .*fresh-cluster-/mu);
});

test("launcher rejects duplicate arguments and computed dynamic imports", () => {
  assert.equal(__test.parseArguments(args())["--expected-commit"],
    "a".repeat(40));
  const duplicate = args();
  duplicate[2] = duplicate[0];
  assert.throws(() => __test.parseArguments(duplicate),
    /FRESH_CLUSTER_LAUNCH_ARGUMENTS_REJECTED/u);
  assert.throws(() => __test.parseImportSpecifiers(
    "const path = './unsafe.js'; import(path);"
  ), /FRESH_CLUSTER_LAUNCH_IMPORT_GRAPH_REJECTED/u);
});

test("protected workflow reaches combined runner only through launcher", () => {
  assert.equal((WORKFLOW.match(
    /node scripts\/launch-fresh-cluster-provider\.js/gu
  ) ?? []).length, 2);
  assert.doesNotMatch(WORKFLOW,
    /node scripts\/run-fresh-cluster-provider\.js/u);
});

test("complete runner graph accepts only the reviewed digest-bound data import", () => {
  const graph = __test.executableGraph(null, false);
  const paths = graph.records.map(({ path: sourcePath }) => sourcePath);
  for (const expected of [
    "release-control/src/release-control-runtime-loader.js",
    "scripts/fresh-recovery-publication-execution.js",
    "scripts/fresh-recovery-source-execution.js",
    "scripts/run-fresh-cluster-provider.js",
    "src/cloud/managed-mcp-client.js",
    "src/cloud/primary-security.js"
  ]) assert.equal(paths.includes(expected), true, expected);
  assert.equal(graph.externalDependencies.includes("pg"), true);
  assert.equal(graph.fileCount > 20, true);
  assert.match(graph.graphSha256, /^[0-9a-f]{64}$/u);
  assert.throws(() => __test.parseImportSpecifiers(
    "const bytes = Buffer.from('x');\n" +
    "const module = await import(`data:text/javascript;base64,${bytes}`);",
    "scripts/not-reviewed.js"
  ), /FRESH_CLUSTER_LAUNCH_IMPORT_GRAPH_REJECTED/u);
});
