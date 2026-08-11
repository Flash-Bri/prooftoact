import assert from "node:assert/strict";
import test from "node:test";
import {
  CockroachManagedMcpRecoveryClient,
  readBoundedUtf8Response,
  RECOVERY_MCP_RESPONSE_LIMIT_BYTES
} from "../src/cloud/managed-mcp-client.js";
import { parseStrictJson } from "../src/cloud/strict-json.js";
import { renderRecoveryQuery } from "../src/cloud/recovery-store.js";

const CLUSTER_ID = "44444444-4444-4444-8444-444444444444";
const TENANT_ID = "22222222-2222-4222-8222-222222222222";
const SESSION_ID = "11111111-1111-4111-8111-111111111111";
const SUBJECT_HASH = "a".repeat(64);
const SOURCE_DIGEST = "b".repeat(64);
const API_KEY = "synthetic-api-key-that-is-long-enough";

function fixedQuery() {
  return renderRecoveryQuery({
    recoverySessionId: SESSION_ID,
    tenantId: TENANT_ID,
    subjectBindingHash: SUBJECT_HASH,
    sourceDigest: SOURCE_DIGEST
  });
}

async function selectWithToolWireResponse({
  contentType,
  responseBodyForId
}) {
  const client = new CockroachManagedMcpRecoveryClient({
    apiKey: API_KEY,
    clusterId: CLUSTER_ID,
    fetchImpl: async (_url, options) => {
      if (options.method === "DELETE") {
        return new Response(null, { status: 200 });
      }
      const payload = JSON.parse(options.body);
      if (payload.method === "initialize") {
        return new Response(JSON.stringify({
          jsonrpc: "2.0",
          id: payload.id,
          result: {
            protocolVersion: "2025-03-26",
            capabilities: {}
          }
        }), {
          status: 200,
          headers: {
            "content-type": "application/json",
            "mcp-session-id": "synthetic-session"
          }
        });
      }
      if (payload.method === "notifications/initialized") {
        return new Response(null, { status: 202 });
      }
      return new Response(responseBodyForId(payload.id), {
        status: 200,
        headers: { "content-type": contentType }
      });
    }
  });
  try {
    return await client.selectQuery({
      clusterId: CLUSTER_ID,
      database: "tideproof_recovery",
      query: fixedQuery()
    });
  } finally {
    await client.close();
  }
}

function responseTransportBody(contentType, jsonText) {
  return contentType === "application/json"
    ? jsonText
    : `data: ${jsonText}\n\n`;
}

test("Managed MCP bounded reader rejects an oversized advertised body before reading", async () => {
  let cancelled = false;
  let readerRequested = false;
  const response = {
    headers: new Headers({
      "content-length": String(RECOVERY_MCP_RESPONSE_LIMIT_BYTES + 1)
    }),
    body: {
      async cancel() {
        cancelled = true;
      },
      getReader() {
        readerRequested = true;
        throw new Error("reader must not be requested");
      }
    }
  };
  await assert.rejects(
    readBoundedUtf8Response(response),
    /RECOVERY_MCP_RESPONSE_TOO_LARGE/
  );
  assert.equal(readerRequested, false);
  assert.equal(cancelled, true);
});

test("Managed MCP bounded reader cancels a chunked body that crosses its cap", async () => {
  let cancelled = false;
  const response = new Response(
    new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array([1, 2, 3]));
        controller.enqueue(new Uint8Array([4, 5, 6]));
      },
      cancel() {
        cancelled = true;
      }
    })
  );
  await assert.rejects(
    readBoundedUtf8Response(response, { limitBytes: 5 }),
    /RECOVERY_MCP_RESPONSE_TOO_LARGE/
  );
  assert.equal(cancelled, true);
});

test("Managed MCP bounded reader accepts exact-cap UTF-8 and rejects invalid UTF-8", async () => {
  const text = '{"ok":true}';
  const accepted = new Response(text);
  assert.equal(
    await readBoundedUtf8Response(accepted, {
      limitBytes: Buffer.byteLength(text)
    }),
    text
  );
  const invalid = new Response(
    new Uint8Array([0xc3, 0x28]),
    { headers: { "content-type": "application/json" } }
  );
  await assert.rejects(
    readBoundedUtf8Response(invalid),
    /RECOVERY_MCP_RESPONSE_ENCODING_INVALID/
  );
});

test("strict JSON parsing rejects decoded-equivalent and nested duplicate members", () => {
  const options = {
    duplicateCode: "TEST_DUPLICATE",
    invalidCode: "TEST_INVALID"
  };
  for (const text of [
    '{"result":1,"result":2}',
    '{"result":1,"\\u0072esult":2}',
    '{"outer":{"key":1,"\\u006bey":2}}',
    '{"𝄞":1,"\\uD834\\uDD1E":2}',
    '{"__proto__":1,"\\u005f_proto__":2}'
  ]) {
    assert.throws(
      () => parseStrictJson(text, options),
      /TEST_DUPLICATE/u
    );
  }
  for (const text of [
    "1e400",
    '{"value":1,}',
    '\ufeff{"value":1}',
    '{"value":01}'
  ]) {
    assert.throws(() => parseStrictJson(text, options), /TEST_INVALID/u);
  }
  assert.deepEqual(
    parseStrictJson('{"left":{"key":1},"right":{"key":2}}', options),
    { left: { key: 1 }, right: { key: 2 } }
  );
  assert.deepEqual(
    parseStrictJson('{"é":1,"e\\u0301":2}', options),
    { "é": 1, "é": 2 }
  );
});

test("Managed MCP response envelopes are exact across JSON and SSE", async () => {
  const shapeInvalid = /RECOVERY_MCP_RESPONSE_SHAPE_INVALID/u;
  const cases = [
    ["result-and-error-null", (id) =>
      `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":{},"error":null}`, shapeInvalid],
    ["error-and-result-null", (id) =>
      `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"error":{"code":-1,"message":"failed"},"result":null}`, shapeInvalid],
    ["missing-result-and-error", (id) =>
      `{"jsonrpc":"2.0","id":${JSON.stringify(id)}}`, shapeInvalid],
    ["falsy-error-false", (id) =>
      `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"error":false}`, shapeInvalid],
    ["falsy-error-null", (id) =>
      `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"error":null}`, shapeInvalid],
    ["malformed-error-code", (id) =>
      `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"error":{"code":"-1","message":"failed"}}`, shapeInvalid],
    ["malformed-error-message", (id) =>
      `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"error":{"code":-1,"message":""}}`, shapeInvalid],
    ["extra-error-member", (id) =>
      `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"error":{"code":-1,"message":"failed","extra":true}}`, shapeInvalid],
    ["extra-top-level-member", (id) =>
      `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":{},"extra":true}`, shapeInvalid],
    ["numeric-id", () =>
      '{"jsonrpc":"2.0","id":1,"result":{}}',
    /RECOVERY_MCP_RESPONSE_(?:SHAPE_INVALID|SSE_AMBIGUOUS)/u]
  ];
  for (const contentType of ["application/json", "text/event-stream"]) {
    for (const [name, bodyForId, expectedError] of cases) {
      await assert.rejects(
        () => selectWithToolWireResponse({
          contentType,
          responseBodyForId: (id) => responseTransportBody(
            contentType,
            bodyForId(id)
          )
        }),
        expectedError,
        `${contentType}: ${name}`
      );
    }
  }
});

test("Managed MCP rejects duplicate decoded members across JSON and SSE", async () => {
  const cases = [
    ["duplicate-id", (id) =>
      `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"id":${JSON.stringify(id)},"result":{}}`],
    ["escaped-id", (id) =>
      `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"\\u0069d":${JSON.stringify(id)},"result":{}}`],
    ["duplicate-result", (id) =>
      `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":{},"result":null}`],
    ["escaped-result", (id) =>
      `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":{},"\\u0072esult":null}`],
    ["nested-result", (id) =>
      `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":{"outer":{"key":1,"\\u006bey":2}}}`]
  ];
  for (const contentType of ["application/json", "text/event-stream"]) {
    for (const [name, bodyForId] of cases) {
      await assert.rejects(
        () => selectWithToolWireResponse({
          contentType,
          responseBodyForId: (id) => responseTransportBody(
            contentType,
            bodyForId(id)
          )
        }),
        /RECOVERY_MCP_RESPONSE_JSON_DUPLICATE_MEMBER/u,
        `${contentType}: ${name}`
      );
    }
  }
});

test("Managed MCP validates every SSE payload before correlation", async () => {
  await assert.rejects(
    () => selectWithToolWireResponse({
      contentType: "text/event-stream",
      responseBodyForId: (id) => [
        'data: {"jsonrpc":"2.0","id":"uncorrelated","result":{"key":1,"\\u006bey":2}}',
        "",
        `data: {"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":{}}`,
        ""
      ].join("\n")
    }),
    /RECOVERY_MCP_RESPONSE_JSON_DUPLICATE_MEMBER/u
  );
});

test("Managed MCP SSE requires one blank-line-dispatched exact correlated response", async () => {
  const exact = (id) =>
    `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":{"rows":[]}}`;
  const rejected = [
    [
      "valid wrong id before correct",
      (id) => `data: ${exact("wrong-id")}\n\ndata: ${exact(id)}\n\n`,
      /RECOVERY_MCP_RESPONSE_ID_MISMATCH/u
    ],
    [
      "malformed wrong id before correct",
      (id) =>
        `data: {"jsonrpc":"2.0","id":"wrong-id","result":{},"extra":true}\n\n` +
        `data: ${exact(id)}\n\n`,
      /RECOVERY_MCP_RESPONSE_SHAPE_INVALID/u
    ],
    [
      "primitive before correct",
      (id) => `data: 1\n\ndata: ${exact(id)}\n\n`,
      /RECOVERY_MCP_RESPONSE_SHAPE_INVALID/u
    ],
    [
      "whitespace-only data event",
      (id) => `data:    \n\ndata: ${exact(id)}\n\n`,
      /RECOVERY_MCP_RESPONSE_SSE_INVALID/u
    ],
    [
      "non-MCP done sentinel",
      (id) => `data: [DONE]\n\ndata: ${exact(id)}\n\n`,
      /RECOVERY_MCP_RESPONSE_SSE_INVALID/u
    ],
    [
      "EOF without a line ending",
      (id) => `data: ${exact(id)}`,
      /RECOVERY_MCP_RESPONSE_SSE_AMBIGUOUS/u
    ],
    [
      "EOF after one LF without a blank event line",
      (id) => `data: ${exact(id)}\n`,
      /RECOVERY_MCP_RESPONSE_SSE_AMBIGUOUS/u
    ],
    [
      "two correlated responses",
      (id) => `data: ${exact(id)}\n\ndata: ${exact(id)}\n\n`,
      /RECOVERY_MCP_RESPONSE_SSE_AMBIGUOUS/u
    ],
    [
      "valid response then unterminated done sentinel",
      (id) => `data: ${exact(id)}\n\ndata: [DONE]`,
      /RECOVERY_MCP_RESPONSE_SSE_AMBIGUOUS/u
    ],
    [
      "valid response then done sentinel without a blank event boundary",
      (id) => `data: ${exact(id)}\n\ndata: [DONE]\n`,
      /RECOVERY_MCP_RESPONSE_SSE_AMBIGUOUS/u
    ],
    [
      "valid response then primitive without a blank event boundary",
      (id) => `data: ${exact(id)}\n\ndata: 7\n`,
      /RECOVERY_MCP_RESPONSE_SSE_AMBIGUOUS/u
    ],
    [
      "valid response then unterminated unknown field bytes",
      (id) => `data: ${exact(id)}\n\ngarbage`,
      /RECOVERY_MCP_RESPONSE_SSE_AMBIGUOUS/u
    ],
    [
      "valid response then keepalive comment without a blank boundary",
      (id) => `data: ${exact(id)}\n\n: keepalive\n`,
      /RECOVERY_MCP_RESPONSE_SSE_AMBIGUOUS/u
    ]
  ];
  for (const [name, responseBodyForId, expectedError] of rejected) {
    await assert.rejects(
      () => selectWithToolWireResponse({
        contentType: "text/event-stream",
        responseBodyForId
      }),
      expectedError,
      name
    );
  }

  const result = await selectWithToolWireResponse({
    contentType: "text/event-stream",
    responseBodyForId: (id) =>
      `: comment\r\ndata: ${exact(id)}\r\n\r\n`
  });
  assert.deepEqual(result, { rows: [] });

  const resultWithCompleteKeepalive = await selectWithToolWireResponse({
    contentType: "text/event-stream",
    responseBodyForId: (id) =>
      `data: ${exact(id)}\n\n: keepalive\n\n`
  });
  assert.deepEqual(resultWithCompleteKeepalive, { rows: [] });
});

test("Managed MCP accepts exact success and error envelopes across JSON and SSE", async () => {
  for (const contentType of ["application/json", "text/event-stream"]) {
    const result = await selectWithToolWireResponse({
      contentType,
      responseBodyForId: (id) => responseTransportBody(
        contentType,
        `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"result":null}`
      )
    });
    assert.equal(result, null);
    await assert.rejects(
      () => selectWithToolWireResponse({
        contentType,
        responseBodyForId: (id) => responseTransportBody(
          contentType,
          `{"jsonrpc":"2.0","id":${JSON.stringify(id)},"error":{"code":-32601,"message":"Method not found","data":[null,{"retry":false}]}}`
        )
      }),
      /RECOVERY_MCP_RPC__32601/u
    );
  }
});

test("Managed MCP client initializes and invokes only fixed select_query", async () => {
  const calls = [];
  let cancelledUnusedBodies = 0;
  const unusedResponse = (status) =>
    new Response(
      new ReadableStream({
        cancel() {
          cancelledUnusedBodies += 1;
        }
      }),
      { status }
    );
  const fetchImpl = async (url, options) => {
    const payload =
      options.body === undefined ? null : JSON.parse(options.body);
    calls.push({ url, options, payload });
    if (options.method === "DELETE") {
      return unusedResponse(200);
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
      return unusedResponse(202);
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
  const evidence = client.transportEvidence();

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
  assert.equal(cancelledUnusedBodies, 2);
  assert.equal(
    evidence.schemaVersion,
    "tideproof.managed-mcp-transport-evidence.v2"
  );
  assert.match(evidence.sessionIdSha256, /^[0-9a-f]{64}$/u);
  assert.equal(evidence.rpcCalls.length, 2);
  assert.equal(evidence.rpcCalls[0].outboundSessionIdSha256, null);
  assert.equal(
    evidence.rpcCalls[0].responseSessionIdSha256,
    evidence.sessionIdSha256
  );
  assert.equal(
    evidence.rpcCalls[1].outboundSessionIdSha256,
    evidence.sessionIdSha256
  );
  assert.equal(evidence.rpcCalls[1].sessionContinuous, true);
  assert.equal(evidence.notifications.length, 1);
  assert.equal(evidence.notifications[0].sessionContinuous, true);
  assert.equal(evidence.close.sessionContinuous, true);
  assert.equal(
    evidence.close.outboundSessionIdSha256,
    evidence.sessionIdSha256
  );
  for (const rpc of evidence.rpcCalls) {
    assert.match(rpc.requestPayloadSha256, /^[0-9a-f]{64}$/u);
    assert.match(rpc.responsePayloadSha256, /^[0-9a-f]{64}$/u);
    assert.match(rpc.resultSha256, /^[0-9a-f]{64}$/u);
    assert.equal(rpc.requestBytes > 0, true);
    assert.equal(rpc.responseBytes > 0, true);
  }
});

test("Managed MCP client rejects a missing or replaced negotiated session", async () => {
  for (const mode of ["missing", "replaced"]) {
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
                ...(mode === "missing"
                  ? {}
                  : { "mcp-session-id": "session-one" })
              }
            }
          );
        }
        if (payload.method === "notifications/initialized") {
          return new Response(null, {
            status: 202,
            headers: { "mcp-session-id": "session-two" }
          });
        }
        throw new Error("tool call must not be reached");
      }
    });
    await assert.rejects(
      client.selectQuery({
        clusterId: CLUSTER_ID,
        database: "tideproof_recovery",
        query: fixedQuery()
      }),
      mode === "missing"
        ? /RECOVERY_MCP_SESSION_REQUIRED/
        : /RECOVERY_MCP_SESSION_CHANGED/
    );
  }
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
    /RECOVERY_MCP_RESPONSE_SHAPE_INVALID/
  );
});

test("Managed MCP client rejects non-normalized or ambiguous content types", async () => {
  for (const contentType of [
    "application/json-malformed",
    "application/json, text/event-stream",
    "application/json; boundary=unexpected",
    "application/json; charset=utf-8; charset=utf-8"
  ]) {
    let fetchCount = 0;
    const client = new CockroachManagedMcpRecoveryClient({
      apiKey: API_KEY,
      clusterId: CLUSTER_ID,
      fetchImpl: async (_url, options) => {
        fetchCount += 1;
        const payload = JSON.parse(options.body);
        return new Response(JSON.stringify({
          jsonrpc: "2.0",
          id: payload.id,
          result: { protocolVersion: "2025-03-26", capabilities: {} }
        }), {
          status: 200,
          headers: {
            "content-type": contentType,
            "mcp-session-id": "synthetic-session"
          }
        });
      }
    });
    await assert.rejects(
      client.selectQuery({
        clusterId: CLUSTER_ID,
        database: "tideproof_recovery",
        query: fixedQuery()
      }),
      /RECOVERY_MCP_CONTENT_TYPE_INVALID/
    );
    assert.equal(fetchCount, 1);
    await client.close();
  }
});

test("Managed MCP SSE rejects malformed, duplicate, or uncorrelated response data", async () => {
  for (const mode of ["malformed", "duplicate", "uncorrelated"]) {
    const client = new CockroachManagedMcpRecoveryClient({
      apiKey: API_KEY,
      clusterId: CLUSTER_ID,
      fetchImpl: async (_url, options) => {
        if (options.method === "DELETE") {
          return new Response(null, { status: 200 });
        }
        const payload = JSON.parse(options.body);
        if (payload.method === "initialize") {
          return new Response(JSON.stringify({
            jsonrpc: "2.0",
            id: payload.id,
            result: {
              protocolVersion: "2025-03-26",
              capabilities: {}
            }
          }), {
            status: 200,
            headers: {
              "content-type": "application/json; charset=UTF-8",
              "mcp-session-id": "synthetic-session"
            }
          });
        }
        if (payload.method === "notifications/initialized") {
          return new Response(null, { status: 202 });
        }
        const response = JSON.stringify({
          jsonrpc: "2.0",
          id: payload.id,
          result: { rows: [] }
        });
        const sse = mode === "malformed"
          ? "data: {not-json}\n\n"
          : mode === "duplicate"
            ? `data: ${response}\n\ndata: ${response}\n\n`
            : `data: ${JSON.stringify({
              jsonrpc: "2.0",
              id: "different-id",
              result: { rows: [] }
            })}\n\n`;
        return new Response(sse, {
          status: 200,
          headers: { "content-type": "text/event-stream; charset=utf-8" }
        });
      }
    });
    try {
      await assert.rejects(
        client.selectQuery({
          clusterId: CLUSTER_ID,
          database: "tideproof_recovery",
          query: fixedQuery()
        }),
        mode === "malformed"
          ? /RECOVERY_MCP_RESPONSE_SSE_INVALID/
          : mode === "uncorrelated"
            ? /RECOVERY_MCP_RESPONSE_ID_MISMATCH/
            : /RECOVERY_MCP_RESPONSE_SSE_AMBIGUOUS/
      );
    } finally {
      await client.close();
    }
  }
});
