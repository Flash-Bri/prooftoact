import assert from "node:assert/strict";
import test from "node:test";

import {
  CockroachManagedMcpJudgeProofClient,
  JUDGE_MANAGED_MCP_TOTAL_DEADLINE_MS
} from "../src/cloud/managed-mcp-client.js";
import { renderJudgeProofQuery } from "../src/cloud/judge-proof-query.js";
import { liveJudgeRow } from "./judge-proof-query.test.js";

const API_KEY = "synthetic-api-key-that-is-long-enough";
const CLUSTER_ID = "44444444-4444-4444-8444-444444444444";
const OBSERVED_AT = Date.parse("2026-09-15T14:00:00.000Z");

function clientWith(fetchImpl, extra = {}) {
  return new CockroachManagedMcpJudgeProofClient({
    apiKey: API_KEY,
    clusterId: CLUSTER_ID,
    now: () => OBSERVED_AT,
    fetchImpl,
    ...extra
  });
}

function successfulFetch(calls, { closeStatus = 204 } = {}) {
  return async (url, options) => {
    const payload = options.body === undefined ? null : JSON.parse(options.body);
    calls.push({ url, options, payload });
    if (options.method === "DELETE") {
      return new Response(null, { status: closeStatus });
    }
    if (payload.method === "initialize") {
      return new Response(JSON.stringify({
        jsonrpc: "2.0",
        id: payload.id,
        result: { protocolVersion: "2025-03-26", capabilities: {} }
      }), {
        status: 200,
        headers: {
          "content-type": "application/json",
          "mcp-session-id": "judge-session"
        }
      });
    }
    if (payload.method === "notifications/initialized") {
      return new Response(null, { status: 202 });
    }
    return new Response(JSON.stringify({
      jsonrpc: "2.0",
      id: payload.id,
      result: {
        content: [{
          type: "text",
          text: JSON.stringify({ rows: [liveJudgeRow()] })
        }]
      }
    }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };
}

test("judge Managed MCP facade has one no-argument fixed proof operation", async () => {
  const calls = [];
  const client = clientWith(successfulFetch(calls), {
    query: "SELECT * FROM mcp_private.anything",
    database: "defaultdb"
  });
  assert.equal(client.readPinnedJudgeProof.length, 0);
  const receipt = await client.readPinnedJudgeProof();
  assert.deepEqual(
    calls.map(({ payload, options }) => payload?.method ?? options.method),
    ["initialize", "notifications/initialized", "tools/call", "DELETE"]
  );
  const tool = calls[2];
  assert.equal(tool.url, "https://cockroachlabs.cloud/mcp");
  assert.equal(tool.options.headers["mcp-cluster-id"], CLUSTER_ID);
  assert.deepEqual(tool.payload.params, {
    name: "select_query",
    arguments: {
      database: "tideproof_recovery",
      query: renderJudgeProofQuery()
    }
  });
  assert.equal(receipt.proof.bundleDigest.length, 64);
  assert.equal(receipt.status, "LIVE_MANAGED_MCP_READ");
  assert.equal(receipt.observedAt, "2026-09-15T14:00:00.000Z");
  assert.equal(receipt.receiptExpiredContext, true);
  assert.equal(receipt.transport.boundedResponseBytes, 32 * 1024);
  assert.equal(receipt.transport.close.sessionContinuous, true);
  assert.match(receipt.semanticRequestEvidenceSha256, /^[0-9a-f]{64}$/u);
});

test("judge Managed MCP facade closes before rejecting an invalid row", async () => {
  const calls = [];
  const fetchImpl = successfulFetch(calls);
  const client = clientWith(async (url, options) => {
    const response = await fetchImpl(url, options);
    const payload = options.body === undefined ? null : JSON.parse(options.body);
    if (payload?.method !== "tools/call") return response;
    return new Response(JSON.stringify({
      jsonrpc: "2.0",
      id: payload.id,
      result: { content: [{ type: "text", text: '{"rows":[]}' }] }
    }), { status: 200, headers: { "content-type": "application/json" } });
  });
  await assert.rejects(
    client.readPinnedJudgeProof(),
    /JUDGE_PROOF_MCP_RESULT_REJECTED/u
  );
  assert.equal(calls.at(-1).options.method, "DELETE");
});

test("judge Managed MCP facade fails closed when session cleanup fails", async () => {
  const client = clientWith(successfulFetch([], { closeStatus: 500 }));
  await assert.rejects(
    client.readPinnedJudgeProof(),
    /JUDGE_MCP_SESSION_CLOSE_REJECTED/u
  );
});

test("judge Managed MCP facade enforces one total deadline", async () => {
  let fetchCount = 0;
  const values = [0, JUDGE_MANAGED_MCP_TOTAL_DEADLINE_MS + 1];
  const client = clientWith(async () => {
    fetchCount += 1;
    throw new Error("fetch must not be reached");
  }, { now: () => values.shift() });
  await assert.rejects(
    client.readPinnedJudgeProof(),
    /MANAGED_MCP_DEADLINE_EXPIRED/u
  );
  assert.equal(fetchCount, 0);
});
