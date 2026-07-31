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
  const page = await pageResponse.text();
  assert.match(
    page,
    /Memory should preserve evidence—not inherit authority/
  );
  assert.match(page, /LOCAL DETERMINISTIC REPLAY/);
  assert.match(
    page,
    /RECORDED GATE ONE — CockroachDB Cloud, synthetic scope, 2026-07-30/
  );
  assert.match(
    page,
    /GATE TWO — local AWS candidate; live AWS evidence pending/
  );
  assert.match(page, /id="gate-two-proof-state"/);
  assert.match(page, /A TrustAgentic\.ai project/);
  assert.match(
    page,
    /https:\/\/github\.com\/Flash-Bri\/tideproof/
  );
  assert.match(page, /data-act="0"/);
  assert.match(page, /id="previous-step"/);
  assert.match(page, /id="restart-demo"/);
  assert.match(
    page,
    /class="proof-ribbon"[\s\S]*?tabindex="0"/
  );
  assert.match(
    page,
    /id="judge-path"[\s\S]*?tabindex="-1"/
  );
  assert.match(
    page,
    /aria-keyshortcuts="ArrowLeft ArrowRight Space Home"/
  );
  assert.match(page, /src="\/architecture\.svg"/);
  assert.match(
    pageResponse.headers.get("content-security-policy"),
    /default-src 'self'/
  );

  const evidenceResponse = await fetch(
    `http://127.0.0.1:${port}/evidence/gate1-authority`
  );
  assert.equal(evidenceResponse.status, 200);
  assert.match(
    evidenceResponse.headers.get("content-type"),
    /^text\/markdown/
  );
  assert.match(
    await evidenceResponse.text(),
    /100 independent races of 50 concurrent database sessions/
  );

  const faviconResponse = await fetch(
    `http://127.0.0.1:${port}/favicon.svg`
  );
  assert.equal(faviconResponse.status, 200);
  assert.equal(
    faviconResponse.headers.get("content-type"),
    "image/svg+xml"
  );

  const architectureResponse = await fetch(
    `http://127.0.0.1:${port}/architecture.svg`
  );
  assert.equal(architectureResponse.status, 200);
  assert.equal(
    architectureResponse.headers.get("content-type"),
    "image/svg+xml"
  );
  assert.match(
    await architectureResponse.text(),
    /Tideproof evidence, proposal, authority, and recovery boundaries/
  );
});
