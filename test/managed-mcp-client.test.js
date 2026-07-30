import assert from "node:assert/strict";
import test from "node:test";
import { CockroachManagedMcpRecoveryClient } from "../src/cloud/managed-mcp-client.js";
import { renderRecoveryQuery } from "../src/cloud/recovery-store.js";

const CLUSTER_ID = "44444444-4444-4444-8444-444444444444";
const TENANT_ID = "22222222-2222-4222-8222-222222222222";
const SESSION_ID = "11111111-1111-4111-8111-111111111111";
const SUBJECT_HASH = "a".repeat(64);
const API_KEY = "synthetic-api-key-that-is-long-enough";

function fixedQuery() {
  return renderRecoveryQuery({
    recoverySessionId: SESSION_ID,
    tenantId: TENANT_ID,
    subjectBindingHash: SUBJECT_HASH
  });
}

test("Managed MCP client initializes and invokes only fixed select_query", async () => {
  const calls = [];
  const fetchImpl = async (url, options) => {
    const payload =
      options.body === undefined ? null : JSON.parse(options.body);
    calls.push({ url, options, payload });
    if (options.method === "DELETE") {
      return new Response(null, { status: 204 });
    }
    if (payload.method === "initialize") {
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: payload.id,
          result: { protocolVersion: "2025-03-26", capabilities: {} }
        }),
        {
          status: 200,
          headers: {
            "content-type": "application/json",
            "mcp-session-id": "synthetic-session"
          }
        }
      );
    }
    if (payload.method === "notifications/initialized") {
      return new Response(null, { status: 202 });
    }
    return new Response(
      JSON.stringify({
        jsonrpc: "2.0",
        id: payload.id,
        result: {
          content: [{ type: "text", text: JSON.stringify({ rows: [] }) }]
        }
      }),
      { status: 200, headers: { "content-type": "application/json" } }
    );
  };
  const client = new CockroachManagedMcpRecoveryClient({
    apiKey: API_KEY,
    clusterId: CLUSTER_ID,
    fetchImpl
  });
  const result = await client.selectQuery({
    clusterId: CLUSTER_ID,
    database: "tideproof_recovery",
    query: fixedQuery()
  });
  await client.close();

  assert.equal(result.content[0].type, "text");
  assert.deepEqual(
    calls.map((call) => call.payload?.method ?? call.options.method),
    [
      "initialize",
      "notifications/initialized",
      "tools/call",
      "DELETE"
    ]
  );
  const toolCall = calls[2];
  assert.equal(toolCall.url, "https://cockroachlabs.cloud/mcp");
  assert.equal(toolCall.payload.params.name, "select_query");
  assert.deepEqual(toolCall.payload.params.arguments, {
    database: "tideproof_recovery",
    query: fixedQuery()
  });
  assert.equal(
    toolCall.options.headers["mcp-cluster-id"],
    CLUSTER_ID
  );
  assert.equal(
    toolCall.options.headers["Mcp-Session-Id"],
    "synthetic-session"
  );
  assert.equal(toolCall.options.redirect, "error");
});

test("Managed MCP client rejects any query outside the fixed template", async () => {
  let fetchCount = 0;
  const client = new CockroachManagedMcpRecoveryClient({
    apiKey: API_KEY,
    clusterId: CLUSTER_ID,
    fetchImpl: async () => {
      fetchCount += 1;
      throw new Error("fetch must not be reached");
    }
  });
  await assert.rejects(
    client.selectQuery({
      clusterId: CLUSTER_ID,
      database: "tideproof_recovery",
      query: "SELECT * FROM mcp_private.recovery_bundles_v2"
    }),
    /RECOVERY_QUERY_TEMPLATE_MISMATCH/
  );
  assert.equal(fetchCount, 0);
});

test("Managed MCP client rejects cluster and database substitution", async () => {
  const client = new CockroachManagedMcpRecoveryClient({
    apiKey: API_KEY,
    clusterId: CLUSTER_ID,
    fetchImpl: async () => {
      throw new Error("fetch must not be reached");
    }
  });
  await assert.rejects(
    client.selectQuery({
      clusterId: "55555555-5555-4555-8555-555555555555",
      database: "tideproof_recovery",
      query: fixedQuery()
    }),
    /RECOVERY_MCP_CLUSTER_MISMATCH/
  );
  await assert.rejects(
    client.selectQuery({
      clusterId: CLUSTER_ID,
      database: "defaultdb",
      query: fixedQuery()
    }),
    /RECOVERY_MCP_DATABASE_MISMATCH/
  );
});

test("Managed MCP client rejects an unsupported negotiated version", async () => {
  const client = new CockroachManagedMcpRecoveryClient({
    apiKey: API_KEY,
    clusterId: CLUSTER_ID,
    fetchImpl: async (_url, options) => {
      const payload = JSON.parse(options.body);
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: payload.id,
          result: { protocolVersion: "2099-01-01", capabilities: {} }
        }),
        {
          status: 200,
          headers: {
            "content-type": "application/json",
            "mcp-session-id": "synthetic-session"
          }
        }
      );
    }
  });
  await assert.rejects(
    client.selectQuery({
      clusterId: CLUSTER_ID,
      database: "tideproof_recovery",
      query: fixedQuery()
    }),
    /RECOVERY_MCP_INITIALIZATION_INVALID/
  );
});

test("Managed MCP client rejects responses without JSON-RPC 2.0", async () => {
  const client = new CockroachManagedMcpRecoveryClient({
    apiKey: API_KEY,
    clusterId: CLUSTER_ID,
    fetchImpl: async (_url, options) => {
      const payload = JSON.parse(options.body);
      if (payload.method === "initialize") {
        return new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: payload.id,
            result: {
              protocolVersion: "2025-03-26",
              capabilities: {}
            }
          }),
          {
            status: 200,
            headers: {
              "content-type": "application/json",
              "mcp-session-id": "synthetic-session"
            }
          }
        );
      }
      if (payload.method === "notifications/initialized") {
        return new Response(null, { status: 202 });
      }
      return new Response(
        JSON.stringify({
          id: payload.id,
          result: {
            content: [{ type: "text", text: JSON.stringify({ rows: [] }) }]
          }
        }),
        {
          status: 200,
          headers: { "content-type": "application/json" }
        }
      );
    }
  });
  await assert.rejects(
    client.selectQuery({
      clusterId: CLUSTER_ID,
      database: "tideproof_recovery",
      query: fixedQuery()
    }),
    /RECOVERY_MCP_RESPONSE_ID_MISMATCH/
  );
});
