import assert from "node:assert/strict";
import test from "node:test";
import { createTideproofServer } from "../src/server.js";

test("serves the local health and scenario surfaces", async (context) => {
  const server = createTideproofServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  context.after(
    () =>
      new Promise((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve()))
      )
  );

  const { port } = server.address();
  const healthResponse = await fetch(`http://127.0.0.1:${port}/api/health`);
  assert.equal(healthResponse.status, 200);
  assert.deepEqual(await healthResponse.json(), {
    ok: true,
    mode: "local-clean-room"
  });

  const scenarioResponse = await fetch(
    `http://127.0.0.1:${port}/api/scenario`
  );
  assert.equal(scenarioResponse.status, 200);
  const scenario = await scenarioResponse.json();
  assert.ok(Object.values(scenario.invariants).every(Boolean));

  const pageResponse = await fetch(`http://127.0.0.1:${port}/`);
  assert.equal(pageResponse.status, 200);
  assert.match(await pageResponse.text(), /Shared memory that fails closed/);
  assert.match(
    pageResponse.headers.get("content-security-policy"),
    /default-src 'self'/
  );
});
